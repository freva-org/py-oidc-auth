"""Comprehensive tests for fastapi-oidc-auth.

Tests are grouped by area and run against a real Keycloak instance
wherever possible, minimising mocking.
"""

from __future__ import annotations

from typing import Any, Dict

import httpx
import pytest

from py_oidc_auth import OIDCAuth
from py_oidc_auth.auth_base import InvalidRequest
from py_oidc_auth.utils import oidc_request

from .conftest import CLIENT_ID, CLIENT_SECRET


class TestLogoutNoEndSession:
    """Cover the else branch when OIDC provider has no end_session_endpoint."""

    @pytest.fixture
    def auth_no_end_session(self) -> OIDCAuth:
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
        )
        # Fake a discovery doc without end_session_endpoint
        auth.config._oidc_overview = {
            "authorization_endpoint": "https://kc.example.com/auth",
            "token_endpoint": "https://kc.example.com/token",
            "jwks_uri": "https://kc.example.com/jwks",
            "issuer": "https://kc.example.com",
            # no end_session_endpoint!
        }
        return auth

    @pytest.mark.asyncio
    async def test_logout_without_end_session_returns_slash(
        self, auth_no_end_session: OIDCAuth
    ) -> None:
        """No end_session_endpoint and no redirect → returns '/'."""
        result = await auth_no_end_session.logout(None)
        assert result == "/"

    @pytest.mark.asyncio
    async def test_logout_without_end_session_returns_custom_redirect(
        self, auth_no_end_session: OIDCAuth
    ) -> None:
        """No end_session_endpoint but redirect provided → returns that URI."""
        result = await auth_no_end_session.logout("https://example.com/bye")
        assert result == "https://example.com/bye"

    @pytest.mark.asyncio
    async def test_logout_without_end_session_logs_warning(
        self, auth_no_end_session: OIDCAuth, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning about missing end_session_endpoint is logged."""
        with caplog.at_level("WARNING"):
            await auth_no_end_session.logout(None)
        assert "end_session_endpoint" in caplog.text


class TestOIDCAuthInit:
    """Tests for OIDCAuth initialisation."""

    def test_basic_init(self) -> None:
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://localhost/oidc",
            scopes="openid profile",
        )
        assert auth.config.client_id == "test"
        assert auth.config.scopes == ["openid", "profile"]
        assert auth._verifier is None

    @pytest.mark.asyncio
    async def test_lazy_verifier_init(self, oidc_auth: OIDCAuth) -> None:
        """Calling _ensure_auth_initialized creates the verifier."""
        await oidc_auth._ensure_auth_initialized()
        assert oidc_auth._verifier is not None

    def test_unreachable_server(self) -> None:
        auth = OIDCAuth(
            client_id="test",
            discovery_url="http://127.0.0.1:1/broken",
            timeout_sec=1,
        )
        # Discovery will fail silently
        assert auth.config.oidc_overview == {}


class TestOidcRequest:
    """Tests for the oidc_request utility."""

    @pytest.mark.asyncio
    async def test_successful_request(
        self, discovery: Dict[str, Any], refresh_token: str
    ) -> None:
        """A real token refresh via oidc_request."""
        data: Dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
        }
        if CLIENT_SECRET:
            data["client_secret"] = CLIENT_SECRET
        result = await oidc_request(
            discovery["token_endpoint"],
            "POST",
            data=data,
        )
        assert "access_token" in result

    @pytest.mark.asyncio
    async def test_upstream_error(self, discovery: Dict[str, Any]) -> None:
        """Bad request to the token endpoint."""

        with pytest.raises(InvalidRequest) as exc_info:
            await oidc_request(
                discovery["token_endpoint"],
                "POST",
                data={"grant_type": "invalid"},
            )
        assert exc_info.value.status_code >= 400

    @pytest.mark.asyncio
    async def test_unreachable_endpoint(self) -> None:
        with pytest.raises(InvalidRequest) as exc_info:
            await oidc_request(
                "http://127.0.0.1:1/fake",
                "POST",
                timeout=httpx.Timeout(1),
            )
        assert exc_info.value.status_code == 502
