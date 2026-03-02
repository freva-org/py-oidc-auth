"""Route tests that run against all installed backends.

The ``test_server`` fixture is parametrized in conftest.py, so every
test in this module executes once per backend (FastAPI, Flask, Quart,
Tornado, Litestar, Django).
"""

from typing import Optional
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient

from py_oidc_auth import FastApiOIDCAuth, IDToken

from .conftest import CLIENT_ID

# FastAPI/Litestar use 307, Flask/Quart/Tornado/Django use 302
REDIRECT_CODES = (301, 302, 303, 307, 308)

OK_COEDS = (200, 201)


class TestLoginRoute:
    """Tests for GET /auth/v2/login."""

    def test_login_redirects(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/login",
            params={"redirect_uri": "http://localhost/callback"},
            allow_redirects=False,
        )
        assert res.status_code in REDIRECT_CODES
        location = res.headers["location"]
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        assert "code_challenge" in qs
        assert qs["code_challenge_method"] == ["S256"]
        assert qs["client_id"] == [CLIENT_ID]
        assert qs["response_type"] == ["code"]

    def test_login_missing_redirect_uri(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/login",
            allow_redirects=False,
        )
        assert res.status_code == 400

    def test_login_with_offline_access(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/login",
            params={
                "redirect_uri": "http://localhost/callback",
                "offline_access": "true",
            },
            allow_redirects=False,
        )
        assert res.status_code in REDIRECT_CODES
        location = res.headers["location"]
        qs = parse_qs(urlparse(location).query)
        assert "offline_access" in qs.get("scope", [""])[0]

    def test_login_with_prompt(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/login",
            params={
                "redirect_uri": "http://localhost/callback",
                "prompt": "login",
            },
            allow_redirects=False,
        )
        assert res.status_code in REDIRECT_CODES
        qs = parse_qs(urlparse(res.headers["location"]).query)
        assert qs.get("prompt") == ["login"]


class TestCallbackRoute:
    """Tests for GET /auth/v2/callback."""

    def test_callback_missing_params(self, test_server: str) -> None:
        res = requests.get(f"{test_server}/api/test/auth/v2/callback")
        assert res.status_code == 400

    def test_callback_missing_code(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/callback",
            params={"state": "x|y|z"},
        )
        assert res.status_code == 400

    def test_callback_invalid_state_format(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/callback",
            params={"code": "fake", "state": "no-pipes-here"},
        )
        assert res.status_code == 400

    def test_callback_valid_format_bad_code(self, test_server: str) -> None:
        """Valid state format but the code is invalid at Keycloak."""
        res = requests.get(
            f"{test_server}/api/test/auth/v2/callback",
            params={
                "code": "invalid-code",
                "state": "token|http://localhost/cb|verifier",
            },
        )
        assert res.status_code >= 400


class TestTokenRoute:
    """Tests for POST /auth/v2/token."""

    def test_token_refresh(self, test_server: str, refresh_token: str) -> None:
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"refresh-token": refresh_token},
        )
        assert res.status_code in OK_COEDS
        body = res.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert "expires" in body

    def test_token_missing_params(self, test_server: str) -> None:
        res = requests.post(f"{test_server}/api/test/auth/v2/token")
        assert res.status_code == 400

    def test_token_bad_code(self, test_server: str) -> None:
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={
                "code": "bad-code",
                "redirect_uri": "http://localhost/cb",
            },
        )
        assert res.status_code >= 400

    def test_token_bad_refresh_token(self, test_server: str) -> None:
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"refresh-token": "invalid-refresh-token"},
        )
        assert res.status_code >= 400

    def test_token_device_code(self, test_server: str) -> None:
        """Device code with a fake code → should fail at Keycloak."""
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device-code": "fake-device-code"},
        )
        assert res.status_code >= 400


class TestLogoutRoute:
    """Tests for GET /auth/v2/logout."""

    def test_logout_redirects(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/logout",
            allow_redirects=False,
        )
        assert res.status_code in REDIRECT_CODES

    def test_logout_with_redirect_uri(self, test_server: str) -> None:
        redirect_uri = "https://example.com/after-logout"
        res = requests.get(
            f"{test_server}/api/test/auth/v2/logout",
            params={"post_logout_redirect_uri": redirect_uri},
            allow_redirects=False,
        )
        assert res.status_code in REDIRECT_CODES
        location = res.headers["location"]
        assert "after-logout" in location

    def test_logout_default_redirect(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/logout",
            allow_redirects=False,
        )
        assert res.status_code in REDIRECT_CODES


# =========================================================================
# FastAPI-only tests (uses TestClient, not applicable to other backends)
# =========================================================================


class TestUnreachableOIDCServer:
    """Tests for behaviour when the OIDC server is down (FastAPI-only)."""

    @pytest.fixture
    def broken_auth(self) -> FastApiOIDCAuth:
        return FastApiOIDCAuth(
            client_id="test",
            discovery_url="http://127.0.0.1:1/nonexistent",
            timeout_sec=1,
        )

    @pytest.fixture
    def broken_app(self, broken_auth: FastApiOIDCAuth) -> FastAPI:
        app = FastAPI()

        @app.get("/required")
        async def required(
            token: IDToken = broken_auth.required(),
        ):
            return {"ok": True}

        @app.get("/optional")
        async def optional(
            token: Optional[IDToken] = broken_auth.optional(),
        ):
            return {"token": token is not None}

        return app

    def test_required_returns_503(self, broken_app: FastAPI) -> None:
        with TestClient(broken_app) as client:
            res = client.get(
                "/required",
                headers={"Authorization": "Bearer fake"},
            )
            assert res.status_code == 503

    def test_optional_returns_none(self, broken_app: FastAPI) -> None:
        with TestClient(broken_app) as client:
            res = client.get(
                "/optional",
                headers={"Authorization": "Bearer fake"},
            )
            assert res.status_code == 200
            assert res.json()["token"] is False
