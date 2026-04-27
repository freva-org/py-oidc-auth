"""JWT token broker — issuance, verification and federation.

:class:`TokenBroker` is the orchestrator used by
:class:`~py_oidc_auth.auth_base.OIDCAuth` when ``broker_mode=True``.  It:

* Lazily loads or generates an RSA-2048 signing key via the configured
  :class:`~py_oidc_auth.broker.store.BrokerStore`.
* Mints and verifies RS256 signed JWTs with a configurable ``aud`` claim.
* Manages a peer JWKS cache for cross-instance token acceptance (federation).
  Unknown ``kid`` values trigger a rate-limited lazy refresh backed by sync
  ``httpx`` so that verification stays synchronous.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional, cast

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from jwt.algorithms import RSAAlgorithm

from py_oidc_auth.schema import IDToken

from .store import BrokerStore, JWKDict, JWKSDict

if TYPE_CHECKING:
    from ..schema import Payload

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"
_PEER_JWKS_PATH = "/auth/v2/.well-known/jwks.json"
_PEER_REFRESH_COOLDOWN = 60.0  # seconds between per-peer lazy refresh attempts

# RFC 8693 token type URNs
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_REFRESH = "urn:ietf:params:oauth:token-type:refresh_token"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


class TokenBroker:
    """Issues and verifies broker-scoped RS256 JWTs.

    :param store: Storage backend for keys, sessions and peer JWKS.
    :param issuer: ``iss`` claim written into minted JWTs and used for
        issuer validation of own tokens.
    :param audience: ``aud`` claim written into minted JWTs.
    :param trusted_issuers: Peer instance URLs whose tokens are accepted.
        Peer JWKS are fetched at startup and cached.
    :param jwks_path: Path segment appended to each peer URL when fetching
        JWKS.  Defaults to ``/auth/v2/.well-known/jwks.json``.

    Usage::

        broker = TokenBroker(
            store=create_broker_store("mongodb://localhost/myapp"),
            issuer="https://api.example.org",
            audience="my-api",
        )
        await broker.setup()          # idempotent, call in lifespan
        token, jti = broker.mint(
            sub="janedoe",
            email="jane@example.org",
            roles=["hpcuser"],
        )
        claims = broker.verify(token)
    """

    def __init__(
        self,
        store: BrokerStore,
        issuer: str,
        audience: str,
        trusted_issuers: Optional[list[str]] = None,
        jwks_path: str = _PEER_JWKS_PATH,
    ) -> None:
        self._store = store
        self.issuer = issuer
        self.audience = audience
        self.trusted_issuers: list[str] = trusted_issuers or []
        self._jwks_path = jwks_path

        self._private_key: Optional[RSAPrivateKey] = None
        self._peer_keys: dict[str, RSAPublicKey] = {}
        self._peer_last_refresh: dict[str, float] = {}

        self._init_lock = asyncio.Lock()
        self._ready = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Initialise the store and load all keys.

        Idempotent — safe to call multiple times.  Recommended inside a
        FastAPI ``lifespan`` handler so startup errors surface early.
        """
        async with self._init_lock:
            if self._ready:
                return
            await self._store.setup()
            await self._load_private_key()
            await self._load_all_peer_keys()
            self._ready = True

    async def _ensure_ready(self) -> None:
        """Lazy-initialise on first use if ``setup()`` was not called."""
        if not self._ready:
            await self.setup()

    # ------------------------------------------------------------------
    # Signing key
    # ------------------------------------------------------------------

    async def _load_private_key(self) -> None:
        pem = await self._store.load_or_create_signing_key()
        self._private_key = cast(
            "RSAPrivateKey",
            serialization.load_pem_private_key(
                pem.encode(),
                password=None,
            ),
        )

    @property
    def private_key(self) -> RSAPrivateKey:
        """The RSA private key — raises ``RuntimeError`` before :meth:`setup`."""
        if self._private_key is None:
            raise RuntimeError("TokenBroker.setup() must be called before use.")
        return self._private_key

    def _key_id(self) -> str:
        """Short SHA-256 fingerprint of the public key (first 16 hex chars)."""
        der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Federation — peer JWKS
    # ------------------------------------------------------------------

    async def _load_all_peer_keys(self) -> None:
        """Fetch live peer JWKS, persist, then restore stored ones as fallback."""
        if not self.trusted_issuers:
            return

        async with httpx.AsyncClient(timeout=5.0, verify=True) as client:
            for url in self.trusted_issuers:
                await self._fetch_and_store_peer_keys(url, client)

        # Restore any persisted keys for peers that were offline above
        for issuer_url, jwks in await self._store.load_all_peer_jwks():
            self._cache_jwks(jwks)
            logger.debug("Restored peer JWKS from store for %s", issuer_url)

    async def _fetch_and_store_peer_keys(
        self, issuer_url: str, client: httpx.AsyncClient
    ) -> None:
        endpoint = f"{issuer_url.rstrip('/')}{self._jwks_path}"
        try:
            resp = await client.get(endpoint)
            resp.raise_for_status()
            jwks: JWKSDict = resp.json()
            await self._store.save_peer_jwks(issuer_url, jwks)
            self._cache_jwks(jwks)
            self._peer_last_refresh[issuer_url] = time.monotonic()
            logger.info(
                "Loaded peer JWKS from %s (%d keys cached)",
                issuer_url,
                len(self._peer_keys),
            )
        except Exception as exc:
            logger.warning("Could not fetch peer JWKS from %s: %s", issuer_url, exc)

    def _cache_jwks(self, jwks: JWKSDict) -> None:
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid") if isinstance(jwk, dict) else None
            if kid:
                self._peer_keys[str(kid)] = cast(
                    RSAPublicKey,
                    RSAAlgorithm.from_jwk(jwk),  # type: ignore
                )

    def _maybe_refresh_peer_keys_for(self, kid: str) -> None:
        """Synchrize JWKS refresh for unknown ``kid``, rate-limited."""
        now = time.monotonic()
        for issuer_url in self.trusted_issuers:
            if (
                now - self._peer_last_refresh.get(issuer_url, 0.0)
                < _PEER_REFRESH_COOLDOWN
            ):
                continue
            endpoint = f"{issuer_url.rstrip('/')}{self._jwks_path}"
            try:
                resp = httpx.get(endpoint, timeout=3.0, verify=True)
                resp.raise_for_status()
                jwks = cast(JWKSDict, resp.json())
                self._cache_jwks(jwks)
                self._peer_last_refresh[issuer_url] = now
                logger.info("Lazily refreshed peer JWKS from %s", issuer_url)
                # Persist to store so other workers pick it up on next startup
                # fire-and-forget — don't block verify()
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self._store.save_peer_jwks(issuer_url, jwks))
                except RuntimeError:
                    pass  # no running loop (e.g. test context) — will persist on next startup
                if kid in self._peer_keys:
                    return
            except Exception as exc:
                logger.warning("Lazy JWKS refresh failed for %s: %s", issuer_url, exc)
                self._peer_last_refresh[issuer_url] = now

    # ------------------------------------------------------------------
    # Public JWT API
    # ------------------------------------------------------------------

    def mint(
        self,
        sub: str,
        email: Optional[str],
        roles: list[str],
        preferred_username: Optional[str] = None,
        expiry_seconds: int = 3600,
    ) -> tuple[str, str]:
        """Mint a signed broker JWT.

        :param sub: Subject (human-readable username).
        :param email: Email address or ``None``.
        :param roles: Flat list of role strings.
        :param preferred_username: Display name; defaults to ``sub``.
        :param expiry_seconds: Token lifetime in seconds.
        :returns: ``(encoded_jwt, jti)`` tuple.
        """
        jti = str(uuid.uuid4())
        now = datetime.now(tz=timezone.utc)
        payload: dict[str, object] = {
            "sub": sub,
            "preferred_username": preferred_username or sub,
            "email": email,
            "roles": roles,
            "jti": jti,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expiry_seconds)).timestamp()),
        }
        token: str = pyjwt.encode(
            payload,
            self.private_key,
            algorithm=ALGORITHM,
            headers={"kid": self._key_id()},
        )
        return token, jti

    def verify(self, token: str) -> IDToken:
        """Verify a broker JWT and return decoded claims.

        Accepts both own tokens and tokens from trusted peer instances.
        An unknown ``kid`` triggers a rate-limited lazy JWKS refresh.

        :param token: Encoded JWT string.
        :returns: Decoded :class:`~py_oidc_auth.schema.IDToken`.
        :raises pyjwt.PyJWTError: For invalid, expired or wrong-audience tokens.
        :raises pyjwt.InvalidIssuerError: For untrusted peer issuers.
        """
        header = pyjwt.get_unverified_header(token)
        kid: Optional[str] = header.get("kid")
        own_kid = self._key_id()

        if kid and kid != own_kid:
            # Not our key — check issuer before touching the peer cache
            unverified: dict[str, Any] = pyjwt.decode(
                token, options={"verify_signature": False}
            )
            iss = str(unverified.get("iss", ""))
            if iss not in self.trusted_issuers:
                raise pyjwt.exceptions.InvalidIssuerError(f"Untrusted issuer: {iss!r}")

            if kid not in self._peer_keys:
                self._maybe_refresh_peer_keys_for(kid)

            if kid in self._peer_keys:
                payload: dict[str, Any] = pyjwt.decode(
                    token,
                    self._peer_keys[kid],
                    algorithms=[ALGORITHM],
                    audience=self.audience,
                    # iss is not checked for peers — they have a different iss
                )
                return IDToken(**payload)

        # Own key (or unresolved peer kid → falls through to own-key path
        # which will raise a signature error, correct behaviour)
        payload = pyjwt.decode(
            token,
            self.private_key.public_key(),
            algorithms=[ALGORITHM],
            audience=self.audience,
            issuer=self.issuer,
        )
        return IDToken(**payload)

    def jwks(self) -> JWKSDict:
        """Return the public key as a JWKS document for the ``/.well-known/jwks.json`` endpoint."""
        jwk: JWKDict = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        jwk["kid"] = self._key_id()
        jwk.setdefault("use", "sig")
        jwk.setdefault("alg", ALGORITHM)
        return JWKSDict({"keys": [jwk]})

    # ------------------------------------------------------------------
    # Session delegation (pass-through to store)
    # ------------------------------------------------------------------

    async def save_session(
        self,
        jti: str,
        sub: Optional[str],
        refresh_token: str,
        expires_at: int,
        user_info: str = "",
    ) -> None:
        """Persist an IDP refresh-token session keyed by ``jti``."""
        await self._store.save_session(
            jti=jti,
            sub=sub or "",
            refresh_token=refresh_token,
            expires_at=expires_at,
            user_info=user_info,
        )

    async def get_session(self, jti: str) -> Optional[tuple[str, str]]:
        """Return ``(sub, refresh_token)`` or ``None``."""
        session = await self._store.get_session(jti)
        if session:
            return session["sub"], session["refresh_token"]
        return None

    async def get_user_info(self, jti: str) -> Dict[str, "Payload"]:
        """Get the user_info content."""
        session = await self._store.get_session(jti)
        user_info: Dict[str, "Payload"] = json.loads(session.get("user_info") or "{}")
        return user_info

    async def delete_session(self, jti: str) -> None:
        """Remove a session entry."""
        await self._store.delete_session(jti)

    async def load_peer_keys(self) -> None:
        """Re-fetch all peer JWKS (e.g. from a scheduled background task)."""
        await self._load_all_peer_keys()
