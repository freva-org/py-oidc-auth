"""Tests for device flow, userinfo, and checkuser endpoints.

Device flow tests mock the upstream httpx response since the test
Keycloak may not have device authorization enabled. All tests use
the parametrized ``test_server`` fixture and therefore run against
every installed backend.

Mocking strategy: we patch ``httpx.AsyncClient.request`` to return
real ``httpx.Response`` objects.  This means the actual
``oidc_request()`` code runs — including status-code checking and
``InvalidRequest`` raising — so the tests are framework-agnostic.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict
from unittest.mock import AsyncMock

import httpx
import jwt as pyjwt
import requests
from pytest_mock import MockerFixture

# ---------------------------------------------------------------------------
# Helpers – fake httpx responses
# ---------------------------------------------------------------------------


def _httpx_response(
    status_code: int = 200,
    payload: Any = None,
    text: str = "",
) -> httpx.Response:
    """Build a real ``httpx.Response`` suitable for mocking."""
    if payload is not None:
        content = json.dumps(payload).encode()
        headers = {"content-type": "application/json"}
    else:
        content = text.encode()
        headers = {"content-type": "text/plain"}
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers=headers,
    )


def _device_start_payload(**overrides: Any) -> Dict[str, Any]:
    base = {
        "device_code": "DEV-123",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://auth.example.com/verify",
        "verification_uri_complete": (
            "https://auth.example.com/verify?user_code=ABCD-EFGH"
        ),
        "expires_in": 600,
        "interval": 2,
    }
    base.update(overrides)
    return base


def _token_success_payload() -> Dict[str, Any]:
    now = int(time.time())
    encoded = pyjwt.encode(
        {"result": "test_access_token", "iat": now, "exp": now + 300},
        "secret",
    )
    return {
        "access_token": encoded,
        "token_type": "Bearer",
        "expires": now + 300,
        "refresh_token": "test_refresh_token",
        "refresh_expires": now + 3600,
        "scope": "profile email address",
    }


_MOCK_TARGET = "httpx.AsyncClient.request"


# ---------------------------------------------------------------------------
# Device flow tests (mocked upstream)
# ---------------------------------------------------------------------------


class TestDeviceFlowStart:
    """Tests for POST /auth/v2/device."""

    def test_device_start_success(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Successful device authorization start returns codes and URIs."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, _device_start_payload()),
        )
        res = requests.post(f"{test_server}/api/test/auth/v2/device")
        assert res.status_code == 200
        js = res.json()
        assert js["device_code"] == "DEV-123"
        assert js["user_code"] == "ABCD-EFGH"
        assert js["verification_uri"] == "https://auth.example.com/verify"
        assert js["verification_uri_complete"] is not None
        assert js["expires_in"] == 600
        assert js["interval"] == 2

    def test_device_start_without_optional_fields(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """verification_uri_complete is optional."""
        payload = _device_start_payload()
        del payload["verification_uri_complete"]
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, payload),
        )
        res = requests.post(f"{test_server}/api/test/auth/v2/device")
        assert res.status_code == 200
        assert res.json()["verification_uri_complete"] is None

    def test_device_start_upstream_malformed(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Missing required fields from upstream → 502."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, {}),
        )
        res = requests.post(f"{test_server}/api/test/auth/v2/device")
        assert res.status_code == 502
        assert "missing" in res.json()["detail"].lower()

    def test_device_start_missing_device_code(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Partial response missing device_code → 502."""
        payload = _device_start_payload()
        del payload["device_code"]
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, payload),
        )
        res = requests.post(f"{test_server}/api/test/auth/v2/device")
        assert res.status_code == 502

    def test_device_start_upstream_error(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Upstream returns an HTTP 500 → propagated via InvalidRequest."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(
                500, text="Internal Server Error"
            ),
        )
        res = requests.post(f"{test_server}/api/test/auth/v2/device")
        assert res.status_code == 500


class TestDeviceFlowTokenPoll:
    """Tests for POST /auth/v2/token with device-code."""

    def test_device_token_success(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Polling with device-code returns tokens on success."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, _token_success_payload()),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device-code": "DEV-123"},
        )
        assert res.status_code == 200
        js = res.json()
        assert "access_token" in js
        assert "refresh_token" in js
        assert "expires" in js
        assert js["token_type"] == "Bearer"

    def test_device_token_authorization_pending(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """OAuth authorization_pending error is forwarded."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(
                400,
                {"error": "authorization_pending", "error_description": ""},
            ),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device-code": "DEV-123"},
        )
        assert res.status_code == 400

    def test_device_token_slow_down(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """OAuth slow_down error is forwarded."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(
                400, {"error": "slow_down", "error_description": ""},
            ),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device-code": "DEV-123"},
        )
        assert res.status_code == 400

    def test_device_token_expired(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Expired device code is forwarded."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(
                400, {"error": "expired_token", "error_description": ""},
            ),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device-code": "EXPIRED"},
        )
        assert res.status_code == 400

    def test_device_token_missing_fields_in_response(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Upstream returns incomplete token data → 400."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(
                200, {"access_token": "x", "token_type": "Bearer"}
            ),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device-code": "DEV-123"},
        )
        assert res.status_code == 400
        assert "failed" in res.json()["detail"].lower()


class TestCallbackMocked:
    """Tests for GET /auth/v2/callback with mocked upstream."""

    def test_callback_success(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Valid code + state → 200 with token JSON."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, _token_success_payload()),
        )
        res = requests.get(
            f"{test_server}/api/test/auth/v2/callback",
            params={
                "code": "valid-auth-code",
                "state": "random-state|http://localhost/cb|pkce-verifier",
            },
        )
        assert res.status_code == 200
        js = res.json()
        assert "access_token" in js
        assert "refresh_token" in js

    def test_callback_upstream_rejects_code(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """Keycloak rejects the auth code → upstream error forwarded."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(
                400, {"error": "invalid_grant", "error_description": "Code not valid"},
            ),
        )
        res = requests.get(
            f"{test_server}/api/test/auth/v2/callback",
            params={
                "code": "expired-code",
                "state": "random-state|http://localhost/cb|pkce-verifier",
            },
        )
        assert res.status_code == 400


class TestTokenViaCodeExchangeMocked:
    """Tests for POST /auth/v2/token with code (mocked upstream)."""

    def test_code_exchange_success(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, _token_success_payload()),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={
                "code": "auth-code-123",
                "redirect_uri": "http://localhost/callback",
                "code_verifier": "verifier-abc",
            },
        )
        assert res.status_code == 200
        js = res.json()
        assert "access_token" in js
        decoded = pyjwt.decode(
            js["access_token"], options={"verify_signature": False}
        )
        assert decoded["result"] == "test_access_token"

    def test_code_exchange_without_redirect_uses_default(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        """When redirect_uri is omitted, the default from config.proxy is used."""
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, _token_success_payload()),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"code": "auth-code-123"},
        )
        assert res.status_code == 200

    def test_refresh_token_success(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=_httpx_response(200, _token_success_payload()),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"refresh-token": "some-refresh-token"},
        )
        assert res.status_code == 200
        assert "access_token" in res.json()
