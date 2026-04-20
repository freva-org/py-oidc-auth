"""Tests for the token broker: store backends, TokenBroker, and OIDCAuth broker methods.

Coverage targets
----------------
* InMemoryBrokerStore  — all methods including expiry
* BrokerStore.get_default_broker_store  — site path + fallback
* SQLAlchemyBrokerStore  — key creation race, session CRUD, peer JWKS, WAL setup
* MongoDBBrokerStore  — tested via InMemory duck-typing (no real Mongo needed)
* create_broker_store  — all URL schemes including normalisation
* TokenBroker  — mint, verify (own key, peer key, untrusted, unknown kid),
                 lazy refresh (persist task, cooldown, failure),
                 federation startup load, session delegation
* OIDCAuth  — _validate_broker_config, _ensure_broker_ready,
              broker_jwks, broker_token (all branches),
              mint_and_store, broker_refresh, broker_exchange
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from py_oidc_auth.broker.issuer import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS,
    TokenBroker,
    _PEER_REFRESH_COOLDOWN,
)
from py_oidc_auth.broker.store import (
    BrokerStore,
    InMemoryBrokerStore,
    JWKDict,
    JWKSDict,
    SQLAlchemyBrokerStore,
    create_broker_store,
)
from py_oidc_auth.schema import IDToken, Token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_peer_broker(issuer_url: str = "https://peer.example.org") -> TokenBroker:
    """Create an in-memory TokenBroker acting as a peer instance."""
    store = InMemoryBrokerStore()
    store._signing_key = _generate_pem()
    broker = TokenBroker(store=store, issuer=issuer_url, audience="test-api")
    # Wire up private key directly so setup() is not needed
    from cryptography.hazmat.primitives import serialization
    broker._private_key = serialization.load_pem_private_key(
        store._signing_key.encode(), password=None
    )
    broker._ready = True
    return broker


def _generate_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def _peer_jwks_httpx_response(peer: TokenBroker) -> httpx.Response:
    return httpx.Response(
        status_code=200,
        content=json.dumps(dict(peer.jwks())).encode(),
        headers={"content-type": "application/json"},
        request=httpx.Request("GET", f"{peer.issuer}/jwks"),
    )


async def _make_ready_broker(
    issuer: str = "https://api.example.org",
    audience: str = "test-api",
    trusted_issuers: Optional[list[str]] = None,
) -> TokenBroker:
    store = InMemoryBrokerStore()
    broker = TokenBroker(
        store=store,
        issuer=issuer,
        audience=audience,
        trusted_issuers=trusted_issuers,
    )
    await broker.setup()
    return broker


def _fake_idp_token(
    sub: str = "janedoe",
    email: str = "jane@example.org",
    expires_in: int = 3600,
) -> Token:
    now = int(time.time())
    return Token(
        access_token=pyjwt.encode(
            {"sub": sub, "email": email, "exp": now + expires_in},
            "secret",
        ),
        token_type="Bearer",
        expires=now + expires_in,
        refresh_token="idp-refresh-xyz",
        refresh_expires=now + 7200,
        scope="openid profile email",
    )


def _fake_idp_claims(sub: str = "janedoe") -> IDToken:
    return IDToken(
        sub=sub,
        preferred_username=sub,
        email=f"{sub}@example.org",
        aud=["test"],
        realm_access={"roles": ["offline_access"]},
    )


# ---------------------------------------------------------------------------
# BrokerStore.get_default_broker_store
# ---------------------------------------------------------------------------


class TestGetDefaultBrokerStore:
    def test_returns_sqlite_url(self) -> None:
        url = BrokerStore.get_default_broker_store("my-app")
        assert url.startswith("sqlite+aiosqlite:///")
        assert "my-app" in url
        assert "broker.sqlite" in url

    def test_falls_back_to_user_data_on_permission_error(self) -> None:
        with patch("platformdirs.site_data_path", side_effect=PermissionError):
            url = BrokerStore.get_default_broker_store("my-app")
        assert url.startswith("sqlite+aiosqlite:///")

    def test_falls_back_to_user_data_on_os_error(self) -> None:
        with patch("platformdirs.site_data_path", side_effect=OSError):
            url = BrokerStore.get_default_broker_store("my-app")
        assert url.startswith("sqlite+aiosqlite:///")


# ---------------------------------------------------------------------------
# create_broker_store factory
# ---------------------------------------------------------------------------


class TestCreateBrokerStore:
    def test_memory(self) -> None:
        store = create_broker_store("memory://")
        assert isinstance(store, InMemoryBrokerStore)

    def test_sqlite_aiosqlite(self, tmp_path: Any) -> None:
        url = f"sqlite+aiosqlite:///{tmp_path}/broker.sqlite"
        store = create_broker_store(url)
        assert isinstance(store, SQLAlchemyBrokerStore)
        assert store._is_sqlite

    def test_sqlite_bare_normalised(self, tmp_path: Any) -> None:
        url = f"sqlite:///{tmp_path}/broker.sqlite"
        store = create_broker_store(url)
        assert isinstance(store, SQLAlchemyBrokerStore)

    def test_tilde_expansion(self) -> None:
        url = "sqlite+aiosqlite:///~/broker.sqlite"
        store = create_broker_store(url)
        assert isinstance(store, SQLAlchemyBrokerStore)
        assert "~" not in str(store._engine.url)

    def test_postgresql(self) -> None:
        url = "postgresql+asyncpg://user:pw@host/db"
        store = create_broker_store(url)
        assert isinstance(store, SQLAlchemyBrokerStore)
        assert not store._is_sqlite

    def test_mysql(self) -> None:
        url = "mysql+aiomysql://user:pw@host/db"
        store = create_broker_store(url)
        assert isinstance(store, SQLAlchemyBrokerStore)

    def test_default_when_none(self) -> None:
        store = create_broker_store(None, "my-app")
        assert isinstance(store, SQLAlchemyBrokerStore)

    def test_unsupported_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            create_broker_store("redis://localhost")

    def test_mongodb(self) -> None:
        from py_oidc_auth.broker.store import MongoDBBrokerStore
        url = "mongodb://localhost/mydb"
        # MongoDBBrokerStore requires pymongo — skip if not installed
        pytest.importorskip("pymongo")
        store = create_broker_store(url)
        assert isinstance(store, MongoDBBrokerStore)


# ---------------------------------------------------------------------------
# InMemoryBrokerStore
# ---------------------------------------------------------------------------


class TestInMemoryBrokerStore:
    @pytest.mark.asyncio
    async def test_setup_is_idempotent(self) -> None:
        store = InMemoryBrokerStore()
        await store.setup()
        await store.setup()  # second call is a no-op
        assert store._ready

    @pytest.mark.asyncio
    async def test_load_or_create_signing_key_creates_and_caches(self) -> None:
        store = InMemoryBrokerStore()
        key1 = await store.load_or_create_signing_key()
        key2 = await store.load_or_create_signing_key()
        assert key1 == key2
        assert key1.startswith("-----BEGIN RSA PRIVATE KEY-----")

    @pytest.mark.asyncio
    async def test_session_save_get_delete(self) -> None:
        store = InMemoryBrokerStore()
        jti = str(uuid.uuid4())
        expires_at = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        await store.save_session(jti, "janedoe", "refresh-xyz", expires_at)

        result = await store.get_session(jti)
        assert result == ("janedoe", "refresh-xyz")

        await store.delete_session(jti)
        assert await store.get_session(jti) is None

    @pytest.mark.asyncio
    async def test_get_session_returns_none_for_unknown(self) -> None:
        store = InMemoryBrokerStore()
        assert await store.get_session("nonexistent") is None

    @pytest.mark.asyncio
    async def test_session_expired_returns_none(self) -> None:
        store = InMemoryBrokerStore()
        jti = str(uuid.uuid4())
        past = int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp())
        await store.save_session(jti, "user", "token", past)
        assert await store.get_session(jti) is None
        # Also confirm it was cleaned up
        assert jti not in store._sessions

    @pytest.mark.asyncio
    async def test_delete_nonexistent_is_noop(self) -> None:
        store = InMemoryBrokerStore()
        await store.delete_session("does-not-exist")  # must not raise

    @pytest.mark.asyncio
    async def test_peer_jwks_save_and_load(self) -> None:
        store = InMemoryBrokerStore()
        jwks = JWKSDict(keys=[JWKDict(kty="RSA", n="abc", e="AQAB", kid="k1", use="sig", alg="RS256")])
        await store.save_peer_jwks("https://peer.example.org", jwks)

        result = await store.load_all_peer_jwks()
        assert len(result) == 1
        assert result[0][0] == "https://peer.example.org"

    @pytest.mark.asyncio
    async def test_load_all_peer_jwks_empty(self) -> None:
        store = InMemoryBrokerStore()
        assert await store.load_all_peer_jwks() == []


# ---------------------------------------------------------------------------
# SQLAlchemyBrokerStore
# ---------------------------------------------------------------------------


class TestSQLAlchemyBrokerStore:
    @pytest.mark.asyncio
    async def test_setup_creates_tables(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        assert store._setup_done

    @pytest.mark.asyncio
    async def test_setup_is_idempotent(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        await store.setup()
        assert store._setup_done

    @pytest.mark.asyncio
    async def test_load_or_create_signing_key(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        key1 = await store.load_or_create_signing_key()
        key2 = await store.load_or_create_signing_key()
        assert key1 == key2
        assert "PRIVATE KEY" in key1

    @pytest.mark.asyncio
    async def test_session_crud(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        jti = str(uuid.uuid4())
        expires_at = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        await store.save_session(jti, "user", "refresh", expires_at)

        result = await store.get_session(jti)
        assert result == ("user", "refresh")

        await store.delete_session(jti)
        assert await store.get_session(jti) is None

    @pytest.mark.asyncio
    async def test_session_update_on_duplicate(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        jti = str(uuid.uuid4())
        expires_at = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        await store.save_session(jti, "user", "refresh-v1", expires_at)
        await store.save_session(jti, "user", "refresh-v2", expires_at)

        result = await store.get_session(jti)
        assert result is not None
        assert result[1] == "refresh-v2"

    @pytest.mark.asyncio
    async def test_get_session_expired_returns_none(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        jti = str(uuid.uuid4())
        past = int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp())
        await store.save_session(jti, "user", "refresh", past)
        assert await store.get_session(jti) is None

    @pytest.mark.asyncio
    async def test_purge_expired(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        jti = str(uuid.uuid4())
        past = int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp())
        await store.save_session(jti, "user", "refresh", past)
        removed = await store.purge_expired()
        assert removed >= 1

    @pytest.mark.asyncio
    async def test_peer_jwks_crud(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        await store.setup()
        jwks = JWKSDict(keys=[JWKDict(kty="RSA", n="n", e="e", kid="k1", use="sig", alg="RS256")])
        await store.save_peer_jwks("https://peer.example.org", jwks)
        await store.save_peer_jwks("https://peer.example.org", jwks)  # upsert

        result = await store.load_all_peer_jwks()
        assert len(result) == 1
        assert result[0][0] == "https://peer.example.org"

    @pytest.mark.asyncio
    async def test_sqlite_is_detected(self, tmp_path: Any) -> None:
        store = SQLAlchemyBrokerStore(url=f"sqlite+aiosqlite:///{tmp_path}/b.sqlite")
        assert store._is_sqlite

    @pytest.mark.asyncio
    async def test_non_sqlite_is_detected(self) -> None:
        store = SQLAlchemyBrokerStore(url="postgresql+asyncpg://u:p@h/db")
        assert not store._is_sqlite

    @pytest.mark.asyncio
    async def test_accepts_existing_engine(self, tmp_path: Any) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/eng.sqlite")
        store = SQLAlchemyBrokerStore(db=engine)
        assert store._engine is engine

    def test_raises_without_url_or_db(self) -> None:
        with pytest.raises(ValueError, match="Either"):
            SQLAlchemyBrokerStore()


# ---------------------------------------------------------------------------
# TokenBroker — core
# ---------------------------------------------------------------------------


class TestTokenBrokerSetup:
    @pytest.mark.asyncio
    async def test_setup_is_idempotent(self) -> None:
        broker = await _make_ready_broker()
        first_key = broker._key_id()
        await broker.setup()  # second call — no-op
        assert broker._key_id() == first_key

    @pytest.mark.asyncio
    async def test_private_key_raises_before_setup(self) -> None:
        store = InMemoryBrokerStore()
        broker = TokenBroker(store=store, issuer="https://x.org", audience="a")
        with pytest.raises(RuntimeError, match="setup"):
            _ = broker.private_key

    @pytest.mark.asyncio
    async def test_ensure_ready_triggers_setup(self) -> None:
        store = InMemoryBrokerStore()
        broker = TokenBroker(store=store, issuer="https://x.org", audience="a")
        await broker._ensure_ready()
        assert broker._ready


# ---------------------------------------------------------------------------
# TokenBroker — mint and verify (own key)
# ---------------------------------------------------------------------------


class TestTokenBrokerMintVerify:
    @pytest.mark.asyncio
    async def test_mint_returns_valid_jwt(self) -> None:
        broker = await _make_ready_broker()
        token, jti = broker.mint(
            sub="janedoe",
            email="jane@example.org",
            roles=["hpcuser"],
        )
        claims = broker.verify(token)
        assert claims.preferred_username == "janedoe"
        assert claims.email == "jane@example.org"

    @pytest.mark.asyncio
    async def test_mint_sets_expiry(self) -> None:
        broker = await _make_ready_broker()
        token, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=7200)
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        now = int(time.time())
        assert decoded["exp"] - now > 7100

    @pytest.mark.asyncio
    async def test_mint_preferred_username_defaults_to_sub(self) -> None:
        broker = await _make_ready_broker()
        token, _ = broker.mint(sub="u", email=None, roles=[])
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["preferred_username"] == "u"

    @pytest.mark.asyncio
    async def test_verify_expired_raises(self) -> None:
        broker = await _make_ready_broker()
        token, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            broker.verify(token)

    @pytest.mark.asyncio
    async def test_verify_wrong_audience_raises(self) -> None:
        broker = await _make_ready_broker(audience="correct-aud")
        token, _ = broker.mint(sub="u", email=None, roles=[])
        # Decode and re-encode with wrong aud
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        wrong = pyjwt.encode(
            {**decoded, "aud": "wrong-aud"},
            broker.private_key,
            algorithm="RS256",
        )
        with pytest.raises(pyjwt.PyJWTError):
            broker.verify(wrong)

    @pytest.mark.asyncio
    async def test_verify_wrong_key_raises(self) -> None:
        broker = await _make_ready_broker()
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fake = pyjwt.encode(
            {"sub": "u", "aud": "test-api", "iss": "https://api.example.org",
             "exp": int(time.time()) + 3600},
            wrong_key,
            algorithm="RS256",
        )
        with pytest.raises(pyjwt.PyJWTError):
            broker.verify(fake)


# ---------------------------------------------------------------------------
# TokenBroker — jwks()
# ---------------------------------------------------------------------------


class TestTokenBrokerJWKS:
    @pytest.mark.asyncio
    async def test_jwks_structure(self) -> None:
        broker = await _make_ready_broker()
        jwks = broker.jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key


# ---------------------------------------------------------------------------
# TokenBroker — federation (peer key verification)
# ---------------------------------------------------------------------------


class TestTokenBrokerFederation:
    @pytest.mark.asyncio
    async def test_verify_accepts_cached_peer_token(self) -> None:
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        broker = await _make_ready_broker(trusted_issuers=[peer_url])

        # Inject peer key directly
        broker._peer_keys[peer._key_id()] = peer.private_key.public_key()

        peer_token, _ = peer.mint(sub="peeruser", email=None, roles=[])
        claims = broker.verify(peer_token)
        assert claims.preferred_username == "peeruser"

    @pytest.mark.asyncio
    async def test_verify_rejects_untrusted_issuer(self) -> None:
        evil = _make_peer_broker("https://evil.example.com")
        broker = await _make_ready_broker(trusted_issuers=[])
        evil_token, _ = evil.mint(sub="x", email=None, roles=[])
        with pytest.raises(pyjwt.exceptions.InvalidIssuerError, match="Untrusted"):
            broker.verify(evil_token)

    @pytest.mark.asyncio
    async def test_verify_untrusted_does_not_trigger_http(self) -> None:
        evil = _make_peer_broker("https://evil.example.com")
        broker = await _make_ready_broker(trusted_issuers=[])
        evil_token, _ = evil.mint(sub="x", email=None, roles=[])
        with patch("httpx.get") as mock_get:
            with pytest.raises(pyjwt.exceptions.InvalidIssuerError):
                broker.verify(evil_token)
            mock_get.assert_not_called()

    @pytest.mark.asyncio
    async def test_load_all_peer_keys_fetches_and_persists(self) -> None:
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        broker = await _make_ready_broker(trusted_issuers=[peer_url])

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(peer.jwks())

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("py_oidc_auth.broker.issuer.httpx.AsyncClient", return_value=mock_client):
            await broker._load_all_peer_keys()

        assert peer._key_id() in broker._peer_keys
        # Also persisted to store
        stored = await broker._store.load_all_peer_jwks()
        assert any(url == peer_url for url, _ in stored)

    @pytest.mark.asyncio
    async def test_load_peer_keys_restores_from_store_on_offline_peer(self) -> None:
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        broker = await _make_ready_broker(trusted_issuers=[peer_url])

        # Pre-load JWKS into store
        await broker._store.save_peer_jwks(peer_url, peer.jwks())

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("py_oidc_auth.broker.issuer.httpx.AsyncClient", return_value=mock_client):
            await broker._load_all_peer_keys()

        assert peer._key_id() in broker._peer_keys

    @pytest.mark.asyncio
    async def test_load_peer_keys_noop_when_no_trusted_issuers(self) -> None:
        broker = await _make_ready_broker(trusted_issuers=[])
        with patch("py_oidc_auth.broker.issuer.httpx.AsyncClient") as mock_cls:
            await broker._load_all_peer_keys()
            mock_cls.assert_not_called()


# ---------------------------------------------------------------------------
# TokenBroker — lazy refresh (_maybe_refresh_peer_keys_for)
# ---------------------------------------------------------------------------


class TestLazyRefresh:
    @pytest.mark.asyncio
    async def test_lazy_refresh_fetches_and_caches(self) -> None:
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        broker = await _make_ready_broker(trusted_issuers=[peer_url])
        peer_kid = peer._key_id()
        broker._peer_last_refresh.pop(peer_url, None)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(peer.jwks())

        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp) as mock_get:
            broker._maybe_refresh_peer_keys_for(peer_kid)
            mock_get.assert_called_once()

        assert peer_kid in broker._peer_keys

    @pytest.mark.asyncio
    async def test_lazy_refresh_persists_via_task(self) -> None:
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        broker = await _make_ready_broker(trusted_issuers=[peer_url])
        broker._peer_last_refresh.pop(peer_url, None)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(peer.jwks())

        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp):
            broker._maybe_refresh_peer_keys_for(peer._key_id())
            # Flush the fire-and-forget task
            await asyncio.sleep(0)

        stored = await broker._store.load_all_peer_jwks()
        assert any(url == peer_url for url, _ in stored)

    def test_lazy_refresh_respects_cooldown(self) -> None:
        store = InMemoryBrokerStore()
        broker = TokenBroker(
            store=store, issuer="https://x.org", audience="a",
            trusted_issuers=["https://peer.example.org"]
        )
        broker._ready = True
        broker._peer_last_refresh["https://peer.example.org"] = time.monotonic()

        with patch("py_oidc_auth.broker.issuer.httpx.get") as mock_get:
            broker._maybe_refresh_peer_keys_for("some-kid")
            mock_get.assert_not_called()

    def test_lazy_refresh_sets_cooldown_on_failure(self) -> None:
        peer_url = "https://peer.example.org"
        store = InMemoryBrokerStore()
        broker = TokenBroker(
            store=store, issuer="https://x.org", audience="a",
            trusted_issuers=[peer_url]
        )
        broker._ready = True
        broker._peer_last_refresh.pop(peer_url, None)

        with patch("py_oidc_auth.broker.issuer.httpx.get", side_effect=Exception("timeout")):
            broker._maybe_refresh_peer_keys_for("some-kid")

        assert peer_url in broker._peer_last_refresh

    @pytest.mark.asyncio
    async def test_verify_triggers_lazy_refresh_for_unknown_kid(self) -> None:
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        broker = await _make_ready_broker(trusted_issuers=[peer_url])
        broker._peer_last_refresh.pop(peer_url, None)

        peer_token, _ = peer.mint(sub="u", email=None, roles=[])

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(peer.jwks())

        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp):
            claims = broker.verify(peer_token)

        assert claims.preferred_username == "u"


# ---------------------------------------------------------------------------
# TokenBroker — session delegation
# ---------------------------------------------------------------------------


class TestTokenBrokerSessions:
    @pytest.mark.asyncio
    async def test_save_get_delete(self) -> None:
        broker = await _make_ready_broker()
        jti = str(uuid.uuid4())
        expires_at = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        await broker.save_session(jti, "user", "refresh", expires_at)
        result = await broker.get_session(jti)
        assert result == ("user", "refresh")
        await broker.delete_session(jti)
        assert await broker.get_session(jti) is None

    @pytest.mark.asyncio
    async def test_save_session_none_sub_uses_empty_string(self) -> None:
        broker = await _make_ready_broker()
        jti = str(uuid.uuid4())
        expires_at = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        await broker.save_session(jti, None, "refresh", expires_at)
        result = await broker.get_session(jti)
        assert result is not None
        assert result[0] == ""


# ---------------------------------------------------------------------------
# OIDCAuth — _validate_broker_config
# ---------------------------------------------------------------------------


class TestValidateBrokerConfig:
    def _make_auth(self, broker_mode: bool = False) -> Any:
        from py_oidc_auth import OIDCAuth
        return OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=broker_mode,
            broker_store_obj=InMemoryBrokerStore(),
        )

    def test_broker_without_token_endpoint_raises(self) -> None:
        auth = self._make_auth(broker_mode=True)
        with pytest.raises(ValueError, match="token endpoint"):
            auth._validate_broker_config(has_token_endpoint=False)

    def test_token_endpoint_without_broker_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        auth = self._make_auth(broker_mode=False)
        import logging
        with caplog.at_level(logging.WARNING):
            auth._validate_broker_config(has_token_endpoint=True)
        assert "broker_mode=False" in caplog.text

    def test_broker_with_token_endpoint_ok(self) -> None:
        auth = self._make_auth(broker_mode=True)
        auth._validate_broker_config(has_token_endpoint=True)  # no raise

    def test_no_broker_no_token_endpoint_ok(self) -> None:
        auth = self._make_auth(broker_mode=False)
        auth._validate_broker_config(has_token_endpoint=False)  # no raise


# ---------------------------------------------------------------------------
# OIDCAuth — _ensure_broker_ready
# ---------------------------------------------------------------------------


class TestEnsureBrokerReady:
    @pytest.mark.asyncio
    async def test_returns_same_broker_on_second_call(self) -> None:
        from py_oidc_auth import OIDCAuth
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=InMemoryBrokerStore(),
            broker_audience="test-api",
        )
        b1 = await auth._ensure_broker_ready()
        b2 = await auth._ensure_broker_ready()
        assert b1 is b2

    @pytest.mark.asyncio
    async def test_uses_broker_store_obj_over_url(self) -> None:
        from py_oidc_auth import OIDCAuth
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
            broker_store_url="memory://ignored",
        )
        broker = await auth._ensure_broker_ready()
        assert broker._store is store


# ---------------------------------------------------------------------------
# OIDCAuth — broker_jwks
# ---------------------------------------------------------------------------


class TestOIDCAuthBrokerJWKS:
    @pytest.mark.asyncio
    async def test_broker_jwks_returns_dict(self) -> None:
        from py_oidc_auth import OIDCAuth
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=InMemoryBrokerStore(),
        )
        jwks = await auth.broker_jwks()
        assert "keys" in jwks
        assert jwks["keys"][0]["kty"] == "RSA"

    @pytest.mark.asyncio
    async def test_broker_jwks_raises_without_broker_mode(self) -> None:
        from py_oidc_auth import OIDCAuth
        auth = OIDCAuth(client_id="test", discovery_url="http://localhost/oidc")
        with pytest.raises(RuntimeError, match="broker_mode"):
            await auth.broker_jwks()


# ---------------------------------------------------------------------------
# OIDCAuth — mint_and_store
# ---------------------------------------------------------------------------


class TestOIDCAuthMintAndStore:
    @pytest.mark.asyncio
    async def test_mint_and_store_returns_broker_jwt(self) -> None:
        from py_oidc_auth import OIDCAuth
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=InMemoryBrokerStore(),
            broker_audience="test-api",
        )
        idp_token = _fake_idp_token()
        with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
            with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe"):
                result = await auth.mint_and_store(idp_token, expiry_seconds=3600)

        assert result.access_token == result.refresh_token
        decoded = pyjwt.decode(result.access_token, options={"verify_signature": False})
        assert decoded["preferred_username"] == "janedoe"
        assert decoded["aud"] == "test-api"

    @pytest.mark.asyncio
    async def test_mint_and_store_persists_session(self) -> None:
        from py_oidc_auth import OIDCAuth
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
        )
        idp_token = _fake_idp_token()
        with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
            with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                result = await auth.mint_and_store(idp_token)

        decoded = pyjwt.decode(result.access_token, options={"verify_signature": False})
        jti = decoded["jti"]
        broker = await auth._ensure_broker_ready()
        session = await broker.get_session(jti)
        assert session is not None
        assert session[1] == "idp-refresh-xyz"


# ---------------------------------------------------------------------------
# OIDCAuth — broker_refresh
# ---------------------------------------------------------------------------


class TestOIDCAuthBrokerRefresh:
    @pytest.mark.asyncio
    async def test_broker_refresh_rotates_session(self) -> None:
        from py_oidc_auth import OIDCAuth
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
        )
        idp_token = _fake_idp_token()

        with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
            with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                first = await auth.mint_and_store(idp_token)

        with patch.object(auth, "token", new_callable=AsyncMock, return_value=idp_token):
            with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
                with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                    second = await auth.broker_refresh(first.access_token, "/token")

        assert second.access_token != first.access_token
        # Old session gone
        broker = await auth._ensure_broker_ready()
        old_jti = pyjwt.decode(first.access_token, options={"verify_signature": False})["jti"]
        assert await broker.get_session(old_jti) is None

    @pytest.mark.asyncio
    async def test_broker_refresh_accepts_expired_jwt(self) -> None:
        from py_oidc_auth import OIDCAuth
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
        )
        idp_token = _fake_idp_token()

        with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
            with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                first = await auth.mint_and_store(idp_token)

        # Re-sign with past expiry but same jti
        decoded = pyjwt.decode(first.access_token, options={"verify_signature": False})
        broker = await auth._ensure_broker_ready()
        expired = pyjwt.encode(
            {**decoded, "exp": int(time.time()) - 10},
            broker.private_key,
            algorithm="RS256",
        )

        with patch.object(auth, "token", new_callable=AsyncMock, return_value=idp_token):
            with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
                with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                    result = await auth.broker_refresh(expired, "/token")

        assert result.access_token is not None

    @pytest.mark.asyncio
    async def test_broker_refresh_missing_jti_raises(self) -> None:
        from py_oidc_auth import OIDCAuth
        from py_oidc_auth.exceptions import InvalidRequest
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
        )
        broker = await auth._ensure_broker_ready()
        # Token without jti — must use broker.issuer to pass issuer validation
        no_jti = pyjwt.encode(
            {"sub": "u", "aud": "py-oidc-auth", "iss": broker.issuer,
             "exp": int(time.time()) + 3600},
            broker.private_key,
            algorithm="RS256",
        )
        with pytest.raises(InvalidRequest, match="jti"):
            await auth.broker_refresh(no_jti, "/token")

    @pytest.mark.asyncio
    async def test_broker_refresh_session_not_found_raises(self) -> None:
        from py_oidc_auth import OIDCAuth
        from py_oidc_auth.exceptions import InvalidRequest
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
        )
        broker = await auth._ensure_broker_ready()
        token, _ = broker.mint(sub="u", email=None, roles=[])
        # Don't save a session — get_session returns None
        with pytest.raises(InvalidRequest, match="Session expired"):
            await auth.broker_refresh(token, "/token")

    @pytest.mark.asyncio
    async def test_broker_refresh_invalid_jwt_raises(self) -> None:
        from py_oidc_auth import OIDCAuth
        from py_oidc_auth.exceptions import InvalidRequest
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=InMemoryBrokerStore(),
        )
        with pytest.raises(InvalidRequest, match="Invalid refresh token"):
            await auth.broker_refresh("not.a.jwt", "/token")


# ---------------------------------------------------------------------------
# OIDCAuth — broker_exchange (RFC 8693)
# ---------------------------------------------------------------------------


class TestOIDCAuthBrokerExchange:
    @pytest.mark.asyncio
    async def test_broker_exchange_returns_broker_jwt(self) -> None:
        from py_oidc_auth import OIDCAuth
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=InMemoryBrokerStore(),
            broker_audience="test-api",
        )
        with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
            with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                result = await auth.broker_exchange("idp-access-token")

        decoded = pyjwt.decode(result.access_token, options={"verify_signature": False})
        assert decoded["aud"] == "test-api"

    @pytest.mark.asyncio
    async def test_broker_exchange_stores_empty_refresh_token(self) -> None:
        from py_oidc_auth import OIDCAuth
        store = InMemoryBrokerStore()
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=store,
        )
        with patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims()):
            with patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="u"):
                result = await auth.broker_exchange("idp-access-token")

        broker = await auth._ensure_broker_ready()
        jti = pyjwt.decode(result.access_token, options={"verify_signature": False})["jti"]
        session = await broker.get_session(jti)
        assert session is not None
        assert session[1] == ""  # no IDP refresh token from plain exchange


# ---------------------------------------------------------------------------
# OIDCAuth — broker_token dispatch
# ---------------------------------------------------------------------------


class TestOIDCAuthBrokerToken:
    def _make_auth(self) -> Any:
        from py_oidc_auth import OIDCAuth
        return OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            broker_mode=True,
            broker_store_obj=InMemoryBrokerStore(),
        )

    @pytest.mark.asyncio
    async def test_dispatches_to_broker_exchange_for_rfc8693(self) -> None:
        auth = self._make_auth()
        with patch.object(auth, "broker_exchange", new_callable=AsyncMock) as mock_exc:
            mock_exc.return_value = MagicMock(spec=Token)
            await auth.broker_token(
                token_endpoint="/token",
                grant_type=GRANT_TYPE_TOKEN_EXCHANGE,
                subject_token="idp-tok",
            )
            mock_exc.assert_called_once_with("idp-tok")

    @pytest.mark.asyncio
    async def test_dispatches_to_broker_refresh(self) -> None:
        auth = self._make_auth()
        with patch.object(auth, "broker_refresh", new_callable=AsyncMock) as mock_ref:
            mock_ref.return_value = MagicMock(spec=Token)
            await auth.broker_token(
                token_endpoint="/token",
                refresh_token="some-refresh",
            )
            mock_ref.assert_called_once_with(freva_jwt="some-refresh", token_endpoint="/token")

    @pytest.mark.asyncio
    async def test_dispatches_to_mint_and_store_for_device_code(self) -> None:
        auth = self._make_auth()
        idp_token = _fake_idp_token()
        with patch.object(auth, "token", new_callable=AsyncMock, return_value=idp_token):
            with patch.object(auth, "mint_and_store", new_callable=AsyncMock) as mock_mint:
                mock_mint.return_value = MagicMock(spec=Token)
                await auth.broker_token(
                    token_endpoint="/token",
                    device_code="DEV-123",
                )
                # device code uses 30-day expiry
                mock_mint.assert_called_once_with(idp_token, expiry_seconds=2592000)

    @pytest.mark.asyncio
    async def test_dispatches_to_mint_and_store_for_auth_code(self) -> None:
        auth = self._make_auth()
        idp_token = _fake_idp_token()
        with patch.object(auth, "token", new_callable=AsyncMock, return_value=idp_token):
            with patch.object(auth, "mint_and_store", new_callable=AsyncMock) as mock_mint:
                mock_mint.return_value = MagicMock(spec=Token)
                await auth.broker_token(
                    token_endpoint="/token",
                    code="auth-code",
                    redirect_uri="http://localhost/cb",
                )
                # code flow uses 1-hour expiry
                mock_mint.assert_called_once_with(idp_token, expiry_seconds=3600)


# ---------------------------------------------------------------------------
# MongoDBBrokerStore — fully mocked (no real MongoDB needed)
# ---------------------------------------------------------------------------


def _make_mongo_store() -> Any:
    """Build a MongoDBBrokerStore with a fully mocked AsyncDatabase."""
    from py_oidc_auth.broker.store import MongoDBBrokerStore

    mock_db = MagicMock()

    # sessions collection
    mock_sessions = AsyncMock()
    mock_sessions.create_index = AsyncMock()
    mock_sessions.replace_one = AsyncMock()
    mock_sessions.delete_one = AsyncMock()

    # keys collection
    mock_keys = AsyncMock()
    mock_keys.update_one = AsyncMock()
    mock_keys.replace_one = AsyncMock()

    mock_db.__getitem__ = MagicMock(
        side_effect=lambda name: mock_sessions if name == "broker_sessions" else mock_keys
    )

    store = MongoDBBrokerStore(db=mock_db)
    return store, mock_sessions, mock_keys


class TestMongoDBBrokerStore:
    def test_requires_url_or_db(self) -> None:
        pytest.importorskip("pymongo")
        from py_oidc_auth.broker.store import MongoDBBrokerStore
        with pytest.raises(ValueError, match="Either"):
            MongoDBBrokerStore()

    def test_accepts_db_object(self) -> None:
        pytest.importorskip("pymongo")
        store, _, _ = _make_mongo_store()
        assert store._db is not None

    @pytest.mark.asyncio
    async def test_setup_creates_ttl_index(self) -> None:
        pytest.importorskip("pymongo")
        store, mock_sessions, _ = _make_mongo_store()
        await store.setup()
        mock_sessions.create_index.assert_called_once()
        call_args = mock_sessions.create_index.call_args
        assert call_args[1]["expireAfterSeconds"] == 0
        assert call_args[1]["name"] == "sessions_ttl"

    @pytest.mark.asyncio
    async def test_setup_is_idempotent(self) -> None:
        pytest.importorskip("pymongo")
        store, mock_sessions, _ = _make_mongo_store()
        await store.setup()
        await store.setup()
        mock_sessions.create_index.assert_called_once()  # only once

    @pytest.mark.asyncio
    async def test_load_signing_key_returns_existing(self) -> None:
        pytest.importorskip("pymongo")
        store, _, mock_keys = _make_mongo_store()
        mock_keys.find_one = AsyncMock(return_value={"pem": "existing-pem"})
        result = await store.load_or_create_signing_key()
        assert result == "existing-pem"
        mock_keys.update_one.assert_not_called()

    @pytest.mark.asyncio
    async def test_load_signing_key_creates_when_absent(self) -> None:
        pytest.importorskip("pymongo")
        store, _, mock_keys = _make_mongo_store()
        pem = _generate_pem()
        # First find_one returns None (key absent), second returns the created key
        mock_keys.find_one = AsyncMock(
            side_effect=[None, {"pem": pem}]
        )
        result = await store.load_or_create_signing_key()
        mock_keys.update_one.assert_called_once()
        assert "upsert" in str(mock_keys.update_one.call_args)
        assert result == pem

    @pytest.mark.asyncio
    async def test_load_signing_key_fallback_when_second_find_returns_none(self) -> None:
        """Covers the `else pem` branch when $setOnInsert wins but re-read fails."""
        pytest.importorskip("pymongo")
        store, _, mock_keys = _make_mongo_store()
        mock_keys.find_one = AsyncMock(return_value=None)
        result = await store.load_or_create_signing_key()
        # Should still return a PEM string (the locally generated one)
        assert "PRIVATE KEY" in result

    @pytest.mark.asyncio
    async def test_save_session(self) -> None:
        pytest.importorskip("pymongo")
        store, mock_sessions, _ = _make_mongo_store()
        expires_at = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        await store.save_session("jti-1", "user", "refresh-tok", expires_at)
        mock_sessions.replace_one.assert_called_once()
        doc = mock_sessions.replace_one.call_args[0][1]
        assert doc["_id"] == "jti-1"
        assert doc["sub"] == "user"
        assert doc["refresh_token"] == "refresh-tok"

    @pytest.mark.asyncio
    async def test_get_session_returns_tuple(self) -> None:
        pytest.importorskip("pymongo")
        store, mock_sessions, _ = _make_mongo_store()
        mock_sessions.find_one = AsyncMock(
            return_value={"_id": "jti-1", "sub": "user", "refresh_token": "rt"}
        )
        result = await store.get_session("jti-1")
        assert result == ("user", "rt")

    @pytest.mark.asyncio
    async def test_get_session_returns_none_for_missing(self) -> None:
        pytest.importorskip("pymongo")
        store, mock_sessions, _ = _make_mongo_store()
        mock_sessions.find_one = AsyncMock(return_value=None)
        assert await store.get_session("nonexistent") is None

    @pytest.mark.asyncio
    async def test_delete_session(self) -> None:
        pytest.importorskip("pymongo")
        store, mock_sessions, _ = _make_mongo_store()
        await store.delete_session("jti-1")
        mock_sessions.delete_one.assert_called_once_with({"_id": "jti-1"})

    @pytest.mark.asyncio
    async def test_save_peer_jwks(self) -> None:
        pytest.importorskip("pymongo")
        store, _, mock_keys = _make_mongo_store()
        jwks = JWKSDict(keys=[JWKDict(kty="RSA", n="n", e="e", kid="k1", use="sig", alg="RS256")])
        await store.save_peer_jwks("https://peer.example.org", jwks)
        mock_keys.replace_one.assert_called_once()
        doc = mock_keys.replace_one.call_args[0][1]
        assert doc["issuer_url"] == "https://peer.example.org"
        assert doc["_id"] == f"{store._PEER_PREFIX}https://peer.example.org"

    @pytest.mark.asyncio
    async def test_load_all_peer_jwks(self) -> None:
        pytest.importorskip("pymongo")
        store, _, mock_keys = _make_mongo_store()
        jwks = JWKSDict(keys=[])

        async def _aiter(*args: Any, **kwargs: Any) -> Any:
            yield {"issuer_url": "https://peer.example.org", "jwks": jwks}

        mock_keys.find = MagicMock(return_value=_aiter())
        result = await store.load_all_peer_jwks()
        assert len(result) == 1
        assert result[0][0] == "https://peer.example.org"

    @pytest.mark.asyncio
    async def test_load_all_peer_jwks_empty(self) -> None:
        pytest.importorskip("pymongo")
        store, _, mock_keys = _make_mongo_store()

        async def _aiter_empty(*args: Any, **kwargs: Any) -> Any:
            return
            yield  # make it an async generator

        mock_keys.find = MagicMock(return_value=_aiter_empty())
        result = await store.load_all_peer_jwks()
        assert result == []

    def test_raises_import_error_without_pymongo(self) -> None:
        """When pymongo is not installed, ImportError is raised."""
        import sys
        from py_oidc_auth.broker.store import MongoDBBrokerStore
        real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else None  # type: ignore[union-attr]
        with patch.dict(sys.modules, {"pymongo": None}):
            with pytest.raises((ImportError, TypeError)):
                MongoDBBrokerStore(url="mongodb://localhost/db")


# ---------------------------------------------------------------------------
# Federation — full end-to-end cross-instance token acceptance
# ---------------------------------------------------------------------------


class TestFederationEndToEnd:
    """Two in-memory broker instances — peer mints, local verifies."""

    @pytest.mark.asyncio
    async def test_peer_token_accepted_after_startup_fetch(self) -> None:
        """Startup JWKS fetch → peer token verified without lazy refresh."""
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)

        local = await _make_ready_broker(
            issuer="https://local.example.org",
            audience="test-api",
            trusted_issuers=[peer_url],
        )

        # Simulate startup fetch: inject peer keys directly
        local._peer_keys[peer._key_id()] = peer.private_key.public_key()

        peer_token, _ = peer.mint(sub="peeruser", email="peer@x.org", roles=["hpcuser"])
        claims = local.verify(peer_token)
        assert claims.preferred_username == "peeruser"
        assert claims.email == "peer@x.org"

    @pytest.mark.asyncio
    async def test_peer_token_accepted_via_lazy_refresh(self) -> None:
        """Unknown kid → lazy refresh → peer token verified."""
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)

        local = await _make_ready_broker(
            issuer="https://local.example.org",
            audience="test-api",
            trusted_issuers=[peer_url],
        )
        # No peer keys pre-loaded
        local._peer_last_refresh.pop(peer_url, None)

        peer_token, _ = peer.mint(sub="lazyuser", email=None, roles=[])

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(peer.jwks())

        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp):
            claims = local.verify(peer_token)

        assert claims.preferred_username == "lazyuser"

    @pytest.mark.asyncio
    async def test_token_from_unknown_issuer_rejected(self) -> None:
        """Peer token with untrusted iss → InvalidIssuerError before HTTP."""
        evil_url = "https://evil.example.com"
        evil = _make_peer_broker(evil_url)

        local = await _make_ready_broker(
            trusted_issuers=["https://trusted.example.org"]  # evil not here
        )

        evil_token, _ = evil.mint(sub="x", email=None, roles=[])
        with patch("py_oidc_auth.broker.issuer.httpx.get") as mock_get:
            with pytest.raises(pyjwt.exceptions.InvalidIssuerError):
                local.verify(evil_token)
            mock_get.assert_not_called()

    @pytest.mark.asyncio
    async def test_peer_key_persisted_to_store_after_lazy_refresh(self) -> None:
        """After lazy refresh, the store contains the peer JWKS."""
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        local_store = InMemoryBrokerStore()

        local = TokenBroker(
            store=local_store,
            issuer="https://local.example.org",
            audience="test-api",
            trusted_issuers=[peer_url],
        )
        await local.setup()
        local._peer_last_refresh.pop(peer_url, None)

        peer_token, _ = peer.mint(sub="u", email=None, roles=[])

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(peer.jwks())

        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp):
            local.verify(peer_token)
            await asyncio.sleep(0)  # flush fire-and-forget task

        stored = await local_store.load_all_peer_jwks()
        assert any(url == peer_url for url, _ in stored)

    @pytest.mark.asyncio
    async def test_rotated_peer_key_picked_up_via_lazy_refresh(self) -> None:
        """Key rotation: peer generates new key pair (new kid) → lazy refresh → accepted."""
        peer_url = "https://peer.example.org"

        # Old peer — load its key into local cache
        old_peer = _make_peer_broker(peer_url)
        local = await _make_ready_broker(trusted_issuers=[peer_url])
        local._peer_keys[old_peer._key_id()] = old_peer.private_key.public_key()
        local._peer_last_refresh.pop(peer_url, None)  # bypass cooldown

        # Peer rotates: new broker instance = new RSA key = new kid
        new_peer = _make_peer_broker(peer_url)
        assert new_peer._key_id() != old_peer._key_id()  # sanity check

        peer_token, _ = new_peer.mint(sub="rotated", email=None, roles=[])

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = dict(new_peer.jwks())

        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp):
            claims = local.verify(peer_token)

        assert claims.preferred_username == "rotated"

    @pytest.mark.asyncio
    async def test_load_peer_keys_public_method(self) -> None:
        """load_peer_keys() re-fetches all trusted peer JWKS."""
        peer_url = "https://peer.example.org"
        peer = _make_peer_broker(peer_url)
        local = await _make_ready_broker(trusted_issuers=[peer_url])

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_peer_jwks_httpx_response(peer))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("py_oidc_auth.broker.issuer.httpx.AsyncClient", return_value=mock_client):
            await local.load_peer_keys()

        assert peer._key_id() in local._peer_keys

    @pytest.mark.asyncio
    async def test_fetch_and_store_failure_is_logged_not_raised(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A failing peer during startup is logged and skipped."""
        import logging
        peer_url = "https://peer.example.org"
        local = await _make_ready_broker(trusted_issuers=[peer_url])

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("py_oidc_auth.broker.issuer.httpx.AsyncClient", return_value=mock_client):
            with caplog.at_level(logging.WARNING):
                await local._load_all_peer_keys()  # must not raise

        assert "Could not fetch" in caplog.text


# ---------------------------------------------------------------------------
# InMemoryBrokerStore — concurrent signing key creation
# ---------------------------------------------------------------------------


class TestInMemoryConcurrentKeyCreation:
    @pytest.mark.asyncio
    async def test_concurrent_key_creation_returns_same_key(self) -> None:
        """Multiple concurrent callers all receive the same key."""
        store = InMemoryBrokerStore()
        results = await asyncio.gather(
            *[store.load_or_create_signing_key() for _ in range(10)]
        )
        assert len(set(results)) == 1  # all identical
