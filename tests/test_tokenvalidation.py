import base64
import json
import time
from typing import Any, Dict
from unittest.mock import AsyncMock

import httpx
import jwt as pyjwt
import pytest

from py_oidc_auth.token_validation import JWKSCache, TokenVerifier

from .conftest import CLIENT_ID


class TestTokenVerifierKeyMiss:
    """Cover the KeyError -> InvalidTokenError path in TokenVerifier.verify."""

    @pytest.mark.asyncio
    async def test_kid_not_in_jwks_after_refetch(self) -> None:
        """Token has a kid that doesn't exist in JWKS even after refresh."""
        # Build a JWKSCache that always returns an empty key set
        cache = JWKSCache("https://fake.example.com/jwks")
        cache._keys = {}
        cache._fetched_at = 0  # expired → will try to refetch

        # Mock _fetch to return no keys (simulates JWKS without matching kid)
        cache._fetch = AsyncMock()

        verifier = TokenVerifier(
            jwks_uri="https://fake.example.com/jwks",
            issuer="https://fake.example.com",
            audience="test-client",
        )
        verifier._jwks_cache = cache

        # Craft a token with a kid that won't be found

        header = base64.urlsafe_b64encode(
            json.dumps(
                {"alg": "RS256", "kid": "ghost-kid", "typ": "JWT"}
            ).encode()
        ).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "test"}).encode()
        ).rstrip(b"=")
        fake_token = f"{header.decode()}.{payload.decode()}.fakesig"

        with pytest.raises(pyjwt.InvalidTokenError, match="ghost-kid"):
            await verifier.verify(fake_token)


class TestJWKSCache:
    """Tests for the JWKS key cache."""

    @pytest.fixture
    def jwks_uri(self, discovery: Dict[str, Any]) -> str:
        return discovery["jwks_uri"]

    @pytest.mark.asyncio
    async def test_fetches_keys(self, jwks_uri: str) -> None:
        cache = JWKSCache(jwks_uri)
        # Get a kid from the JWKS directly
        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_uri)
            keys = resp.json()["keys"]
        kid = keys[0]["kid"]
        jwk = await cache.get_key(kid)
        assert jwk["kid"] == kid

    @pytest.mark.asyncio
    async def test_unknown_kid_triggers_refetch(self, jwks_uri: str) -> None:
        cache = JWKSCache(jwks_uri)
        with pytest.raises(KeyError, match="No key with kid="):
            await cache.get_key("nonexistent-kid-12345")

    @pytest.mark.asyncio
    async def test_ttl_expiry_triggers_refetch(self, jwks_uri: str) -> None:
        cache = JWKSCache(jwks_uri, ttl=0)  # Immediately expired
        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_uri)
            kid = resp.json()["keys"][0]["kid"]
        # First fetch
        await cache.get_key(kid)
        first_fetch_time = cache._fetched_at
        # TTL=0 means expired immediately, next call refetches
        time.sleep(0.01)
        await cache.get_key(kid)
        assert cache._fetched_at > first_fetch_time


class TestTokenVerifier:
    """Tests for JWT verification against real Keycloak JWKS."""

    @pytest.fixture
    def verifier(self, discovery: Dict[str, Any]) -> TokenVerifier:
        return TokenVerifier(
            jwks_uri=discovery["jwks_uri"],
            issuer=discovery["issuer"],
            audience=CLIENT_ID,
        )

    @pytest.mark.asyncio
    async def test_verify_valid_token(
        self, verifier: TokenVerifier, access_token: str
    ) -> None:
        from py_oidc_auth import IDToken

        token = await verifier.verify(access_token)
        assert isinstance(token, IDToken)
        assert token.iss is not None
        assert token.sub is not None

    @pytest.mark.asyncio
    async def test_reject_garbage_token(self, verifier: TokenVerifier) -> None:
        with pytest.raises(pyjwt.InvalidTokenError):
            await verifier.verify("not.a.jwt")

    @pytest.mark.asyncio
    async def test_reject_token_without_kid(
        self, verifier: TokenVerifier
    ) -> None:
        # Craft a token with no kid in the header
        token = pyjwt.encode(
            {"sub": "test"},
            "secret",
            algorithm="HS256",
        )
        with pytest.raises(pyjwt.InvalidTokenError, match="Malformed"):
            await verifier.verify(token)

    @pytest.mark.asyncio
    async def test_reject_wrong_audience(
        self, discovery: Dict[str, Any], access_token: str
    ) -> None:
        verifier = TokenVerifier(
            jwks_uri=discovery["jwks_uri"],
            issuer=discovery["issuer"],
            audience="wrong-audience-xxx",
        )
        with pytest.raises(pyjwt.InvalidTokenError):
            await verifier.verify(access_token)

    @pytest.mark.asyncio
    async def test_reject_wrong_issuer(
        self, discovery: Dict[str, Any], access_token: str
    ) -> None:
        verifier = TokenVerifier(
            jwks_uri=discovery["jwks_uri"],
            issuer="https://wrong-issuer.example.com",
            audience=CLIENT_ID,
        )
        with pytest.raises(pyjwt.InvalidTokenError):
            await verifier.verify(access_token)
