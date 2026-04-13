"""JWT validation for OpenID Connect.

This module implements signature verification and claim validation for
JWTs issued by an OpenID Connect provider.

It fetches the provider JSON Web Key Set and caches it to support key
rotation.

Most users interact with this functionality indirectly through
:class:`~py_oidc_auth.auth_base.OIDCAuth`.

"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Callable, Dict, Optional, Sequence, Union

import httpx
import jwt as pyjwt

from .schema import IDToken, Payload

if TYPE_CHECKING:
    from pyjwt.algorithms import AllowedPublicKeys
    from pyjwt.api_jwk import PyJWK
    from pyjwt.types import JWKDict

logger = logging.getLogger(__name__)

_DEFAULT_JWKS_TTL = 3600

FromJwk = Callable[
    [Union[str, "JWKDict"]], Union["AllowedPublicKeys", "PyJWK", str, bytes]
]


class JWKSCache:
    """Fetch and cache a JSON Web Key Set.

    Keys are refreshed when the cache expires or when a token refers to a key id
    that is not currently cached.

    :param jwks_uri: Provider JWKS URI.
    :param ttl: Cache time to live in seconds.
    :param timeout: HTTP timeout for fetching keys.

    """

    def __init__(
        self,
        jwks_uri: str,
        ttl: int = _DEFAULT_JWKS_TTL,
        timeout: Optional[httpx.Timeout] = None,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._ttl = ttl
        self._timeout = timeout or httpx.Timeout(10)
        self._keys: Dict[str, Payload] = {}
        self._fetched_at: float = 0
        self._lock = asyncio.Lock()

    @property
    def _is_expired(self) -> bool:
        return (time.monotonic() - self._fetched_at) >= self._ttl

    async def _fetch(self) -> None:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(self._jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()
        self._keys = {k["kid"]: k for k in jwks.get("keys", []) if "kid" in k}
        self._fetched_at = time.monotonic()
        logger.debug("Fetched %d keys from %s", len(self._keys), self._jwks_uri)

    async def get_key(self, kid: str) -> Payload:
        """Return the JWK for a given key id.

        :param kid: Key id from the JWT header.
        :returns: JWK mapping.
        :raises KeyError: If the provider does not expose a matching key.

        """
        async with self._lock:
            if self._is_expired or kid not in self._keys:
                await self._fetch()
        try:
            return self._keys[kid]
        except KeyError:
            raise KeyError(f"No key with kid={kid!r} in JWKS at {self._jwks_uri}")


class TokenVerifier:
    """Validate JWTs issued by an OpenID Connect provider.

    :param jwks_uri: Provider JWKS URI.
    :param issuer: Expected issuer claim.
    :param audience: Expected audience claim, typically your client id.
    :param algorithms: Accepted signing algorithms.
    :param jwks_ttl: Cache time to live for the JWKS.
    :param timeout: HTTP timeout for fetching keys.
    :param verify_exp: Whether to verify the expiry claim. Default ``True``.
    :param verify_iss: Whether to verify the issuer claim. Default ``True``.
    :param verify_aud: Whether to verify the audience claim. Default ``True``.
    :param verify_nbf: Whether to verify the not-before claim. Default ``True``.

    Example
    -------
    .. code-block:: python

        verifier = TokenVerifier(
            jwks_uri=cfg.oidc_overview["jwks_uri"],
            issuer=cfg.oidc_overview["issuer"],
            audience=cfg.client_id,
        )
        token = await verifier.verify(raw_jwt)

    """

    _ALG_MAP: Dict[str, FromJwk] = {
        "RS256": pyjwt.algorithms.RSAAlgorithm.from_jwk,
        "RS384": pyjwt.algorithms.RSAAlgorithm.from_jwk,
        "RS512": pyjwt.algorithms.RSAAlgorithm.from_jwk,
        "ES256": pyjwt.algorithms.ECAlgorithm.from_jwk,
        "ES384": pyjwt.algorithms.ECAlgorithm.from_jwk,
        "ES512": pyjwt.algorithms.ECAlgorithm.from_jwk,
    }

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        algorithms: Sequence[str] = ("RS256",),
        jwks_ttl: int = _DEFAULT_JWKS_TTL,
        timeout: Optional[httpx.Timeout] = None,
        verify_exp: bool = True,
        verify_iss: bool = True,
        verify_aud: bool = True,
        verify_nbf: bool = True,
    ) -> None:
        self._jwks_cache = JWKSCache(jwks_uri, ttl=jwks_ttl, timeout=timeout)
        self._issuer = issuer
        self._audience = audience
        self._algorithms = list(algorithms)
        self._verify_exp = verify_exp
        self._verify_iss = verify_iss
        self._verify_aud = verify_aud
        self._verify_nbf = verify_nbf

    async def verify(self, token: str) -> IDToken:
        """Decode and validate a JWT.

        :param token: Encoded JWT without the ``Bearer`` prefix.
        :returns: Decoded token as :class:`~py_oidc_auth.schema.IDToken`.
        :raises pyjwt.InvalidTokenError: On any validation failure.

        """
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.DecodeError as exc:
            raise pyjwt.InvalidTokenError(f"Malformed JWT header: {exc}")

        kid = header.get("kid")
        alg = header.get("alg", self._algorithms[0])
        from_jwk = self._ALG_MAP.get(alg)
        if not kid or from_jwk is None:
            raise pyjwt.InvalidTokenError("Malformed JWT header.")

        try:
            jwk_data = await self._jwks_cache.get_key(kid)
        except KeyError:
            raise pyjwt.InvalidTokenError(f"No matching key for kid={kid!r}")

        public_key = from_jwk(jwk_data)

        payload = pyjwt.decode(
            token,
            key=public_key,
            algorithms=self._algorithms,
            issuer=self._issuer,
            audience=self._audience,
            options={
                "verify_exp": self._verify_exp,
                "verify_iss": self._verify_iss,
                "verify_aud": self._verify_aud,
                "verify_nbf": self._verify_nbf,
            },
        )
        return IDToken(**payload)
