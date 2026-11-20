"""Client side PKCE, provider outages, ID tokens and form field names.

Route tests run against every installed backend (``test_server``) and,
where they log in, against the real Keycloak: a small cookie handling
:class:`Browser` fills in Keycloak's login form and stops at the redirect
to the client, as a browser would hand the code to a local callback.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import re
import secrets
from typing import Any, Dict, Optional, Tuple
from unittest.mock import AsyncMock, PropertyMock
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import pytest
import requests
from pytest_mock import MockerFixture

from py_oidc_auth import OIDCAuth
from py_oidc_auth.auth_base import _split_legacy_state
from py_oidc_auth.exceptions import InvalidRequest
from py_oidc_auth.schema import Token
from py_oidc_auth.utils import OIDCConfig

from .conftest import (
    CLIENT_ID,
    DISCOVERY_URL,
    TEST_PASSWORD,
    TEST_USER,
    _find_free_port,
)

REDIRECT_CODES = (301, 302, 303, 307, 308)
# Registered for the freva client in the dev realm; nothing listens there.
CLIENT_CALLBACK = "http://localhost:53100/callback"
_MOCK_TARGET = "httpx.AsyncClient.request"


def pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return verifier, challenge


class Browser:
    """Just enough of a browser for Keycloak's login pages over plain http.

    Keycloak marks its cookies ``Secure`` even on http, which ``requests``
    then refuses to send back, so cookies are kept by hand.
    """

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.trust_env = False
        self.jar: Dict[str, str] = {}

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        cookie = "; ".join(f"{k}={v}" for k, v in self.jar.items())
        res = self.session.request(
            method, url, headers={"Cookie": cookie}, allow_redirects=False, **kwargs
        )
        for raw in res.raw.headers.getlist("Set-Cookie"):
            name, _, rest = raw.partition("=")
            self.jar[name] = rest.split(";", 1)[0]
        return res

    def go(self, method: str, url: str, stop: str, **kwargs: Any) -> Any:
        """Follow redirects; return the URL once one points at ``stop``."""
        res = self._send(method, url, **kwargs)
        while res.status_code in REDIRECT_CODES:
            url = urljoin(url, res.headers["location"])
            if url.startswith(stop):
                return url
            res = self._send("GET", url)
        return res

    def submit(self, page: requests.Response, data: Dict[str, str], stop: str) -> Any:
        found = re.search(r'<form[^>]*action="([^"]+)"', page.text)
        assert found, page.text[:500]
        action = urljoin(page.url, html.unescape(found.group(1)))
        return self.go("POST", action, stop=stop, data=data)

    def login(self, url: str, stop: str = CLIENT_CALLBACK) -> str:
        """Open ``url``, sign in as the test user, return the callback URL."""
        page = self.go("GET", url, stop=stop)
        if isinstance(page, str):  # already signed in
            return page
        result = self.submit(
            page, {"username": TEST_USER, "password": TEST_PASSWORD}, stop
        )
        if not isinstance(result, str) and 'name="accept"' in result.text:
            result = self.submit(result, {"accept": "Yes"}, stop)
        assert isinstance(result, str), result.text[:500]
        return result


def query(url: str) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def login_location(base: str, **params: str) -> str:
    res = requests.get(
        f"{base}/api/test/auth/v2/login",
        params={"redirect_uri": CLIENT_CALLBACK, **params},
        allow_redirects=False,
    )
    assert res.status_code in REDIRECT_CODES, res.text
    return res.headers["location"]


# ---------------------------------------------------------------------------
# Login: client side PKCE
# ---------------------------------------------------------------------------


class TestClientPKCELogin:
    def test_challenge_and_state_pass_through(self, test_server: str) -> None:
        _, challenge = pkce_pair()
        location = login_location(
            test_server, code_challenge=challenge, state="client-state-123"
        )
        qs = query(location)
        assert qs["code_challenge"] == challenge
        assert qs["code_challenge_method"] == "S256"
        assert qs["state"] == "client-state-123"  # nothing of ours in it

    def test_challenge_without_state_gets_one(self, test_server: str) -> None:
        _, challenge = pkce_pair()
        qs = query(login_location(test_server, code_challenge=challenge))
        assert qs["state"] and "|" not in qs["state"]

    @pytest.mark.parametrize(
        "params",
        [
            {"code_challenge_method": "plain"},
            {"code_challenge": "too-short"},
            {"code_challenge": "x" * 42 + "="},
        ],
    )
    def test_bad_challenge_is_400(
        self, test_server: str, params: Dict[str, str]
    ) -> None:
        params = {"code_challenge": pkce_pair()[1], **params}
        res = requests.get(
            f"{test_server}/api/test/auth/v2/login",
            params={"redirect_uri": CLIENT_CALLBACK, **params},
            allow_redirects=False,
        )
        assert res.status_code == 400

    def test_legacy_login_keeps_client_state_first(self, test_server: str) -> None:
        state = query(login_location(test_server, state="mine"))["state"]
        first, redirect_uri, verifier = state.split("|", 2)
        assert first == "mine"
        assert redirect_uri == CLIENT_CALLBACK
        assert verifier

    def test_legacy_login_refuses_pipe_in_state(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/api/test/auth/v2/login",
            params={"redirect_uri": CLIENT_CALLBACK, "state": "a|b"},
            allow_redirects=False,
        )
        assert res.status_code == 400

    def test_end_to_end_with_keycloak(self, test_server: str) -> None:
        """The verifier never leaves the client until it redeems the code."""
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        location = login_location(
            test_server, code_challenge=challenge, state=state, prompt="login"
        )
        assert verifier not in location
        browser = Browser()
        callback = query(browser.login(location))
        assert callback["state"] == state
        token_url = f"{test_server}/api/test/auth/v2/token"

        wrong = requests.post(
            token_url,
            data={
                "code": callback["code"],
                "redirect_uri": CLIENT_CALLBACK,
                "code_verifier": pkce_pair()[0],
            },
        )
        assert wrong.status_code == 400, wrong.text
        assert "PKCE" in wrong.text

        # Keycloak burns a code on any attempt: log in again for the real one.
        location = login_location(test_server, code_challenge=challenge, state=state)
        callback = query(browser.login(location))
        res = requests.post(
            token_url,
            data={
                "code": callback["code"],
                "redirect_uri": CLIENT_CALLBACK,
                "code_verifier": verifier,
            },
        )
        assert res.status_code in (200, 201), res.text
        body = res.json()
        assert body["access_token"]
        assert body["id_token"]

        # With the hint Keycloak ends the session without asking first.
        logout = requests.get(
            f"{test_server}/api/test/auth/v2/logout",
            params={
                "post_logout_redirect_uri": CLIENT_CALLBACK,
                "id_token_hint": body["id_token"],
            },
            allow_redirects=False,
        )
        assert logout.status_code in REDIRECT_CODES
        assert query(logout.headers["location"])["id_token_hint"] == body["id_token"]
        assert browser.go("GET", logout.headers["location"], stop=CLIENT_CALLBACK) == (
            CLIENT_CALLBACK
        )


class TestLegacyState:
    @pytest.mark.parametrize(
        ("state", "redirect_uri", "verifier"),
        [
            ("s|http://localhost/cb|v", "http://localhost/cb", "v"),
            ("s|http://localhost/cb?next=a|b|v", "http://localhost/cb?next=a|b", "v"),
            ("s|http://localhost/cb|x|y|v", "http://localhost/cb|x|y", "v"),
        ],
    )
    def test_split(self, state: str, redirect_uri: str, verifier: str) -> None:
        assert _split_legacy_state(state) == (redirect_uri, verifier)

    @pytest.mark.parametrize(
        "state", ["no-pipes", "s|only-two", "s||v", "s|http://localhost/cb|"]
    )
    def test_split_rejects(self, state: str) -> None:
        with pytest.raises(InvalidRequest) as exc:
            _split_legacy_state(state)
        assert exc.value.status_code == 400

    async def test_callback_keeps_pipe_in_redirect_uri(
        self, mocker: MockerFixture
    ) -> None:
        auth = OIDCAuth(client_id=CLIENT_ID, discovery_url=DISCOVERY_URL)
        redirect_uri = f"{CLIENT_CALLBACK}?next=a|b"
        url = await auth.login(redirect_uri=redirect_uri, prompt="none")
        token = mocker.patch.object(
            auth,
            "token",
            new_callable=AsyncMock,
            return_value=Token(
                access_token="a",
                token_type="Bearer",
                expires=1,
                refresh_token=None,
                refresh_expires=None,
                scope="openid",
            ),
        )
        await auth.callback(code="c", state=query(url)["state"])
        sent = token.call_args.kwargs
        assert sent["redirect_uri"] == redirect_uri
        challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(sent["code_verifier"].encode()).digest()
            )
            .decode()
            .rstrip("=")
        )
        assert challenge == query(url)["code_challenge"]


# ---------------------------------------------------------------------------
# Device flow: PKCE when the client asks for it
# ---------------------------------------------------------------------------


def _device_payload() -> Dict[str, Any]:
    return {
        "device_code": "DEV-123",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://auth.example.com/verify",
        "expires_in": 600,
    }


def _sent_form(mock: AsyncMock) -> Dict[str, str]:
    return dict(mock.call_args.kwargs["data"])


class TestDevicePKCE:
    def test_challenge_is_forwarded(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        mock = mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=httpx.Response(200, json=_device_payload()),
        )
        _, challenge = pkce_pair()
        res = requests.post(
            f"{test_server}/api/test/auth/v2/device",
            data={"code_challenge": challenge, "code_challenge_method": "S256"},
        )
        assert res.status_code == 200, res.text
        sent = _sent_form(mock)
        assert sent["code_challenge"] == challenge
        assert sent["code_challenge_method"] == "S256"

    def test_without_challenge_nothing_is_added(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        mock = mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=httpx.Response(200, json=_device_payload()),
        )
        res = requests.post(f"{test_server}/api/test/auth/v2/device")
        assert res.status_code == 200, res.text
        assert "code_challenge" not in _sent_form(mock)

    def test_bad_challenge_is_400(self, test_server: str) -> None:
        res = requests.post(
            f"{test_server}/api/test/auth/v2/device",
            data={"code_challenge": "nope"},
        )
        assert res.status_code == 400

    def test_poll_sends_verifier(self, test_server: str, mocker: MockerFixture) -> None:
        mock = mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=httpx.Response(
                400,
                json={"error": "authorization_pending"},
            ),
        )
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token",
            data={"device_code": "DEV-123", "code_verifier": "the-verifier"},
        )
        assert res.status_code == 400
        sent = _sent_form(mock)
        assert sent["device_code"] == "DEV-123"
        assert sent["code_verifier"] == "the-verifier"


async def test_device_pkce_with_keycloak() -> None:
    """Keycloak binds the device code to the challenge (needs Keycloak >= 25)."""
    auth = OIDCAuth(client_id=CLIENT_ID, discovery_url=DISCOVERY_URL)
    verifier, challenge = pkce_pair()
    start = await auth.device_flow(code_challenge=challenge)
    _approve_device(start.verification_uri_complete or "")

    # Polling faster than the interval earns "slow_down" instead.
    await asyncio.sleep(start.interval + 1)
    with pytest.raises(InvalidRequest) as missing:
        await auth.token("/t", device_code=start.device_code)
    assert "PKCE" in missing.value.detail
    await asyncio.sleep(start.interval + 1)
    token = await auth.token(
        "/t", device_code=start.device_code, code_verifier=verifier
    )
    assert token.access_token and token.id_token


def _approve_device(url: str) -> None:
    browser = Browser()
    page = browser.go("GET", url, stop="http://never.invalid/")
    page = browser.submit(
        page,
        {"username": TEST_USER, "password": TEST_PASSWORD},
        "http://never.invalid/",
    )
    if 'name="accept"' in page.text:
        page = browser.submit(page, {"accept": "Yes"}, "http://never.invalid/")
    assert page.status_code == 200, page.text[:500]


# ---------------------------------------------------------------------------
# Token endpoint: field names and ID token
# ---------------------------------------------------------------------------


class TestTokenFields:
    @pytest.mark.parametrize("field", ["refresh_token", "refresh-token"])
    def test_both_refresh_field_names(
        self, test_server: str, refresh_token: str, field: str
    ) -> None:
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token", data={field: refresh_token}
        )
        assert res.status_code in (200, 201), res.text
        assert res.json()["access_token"]

    @pytest.mark.parametrize("field", ["device_code", "device-code"])
    def test_both_device_field_names(
        self, test_server: str, mocker: MockerFixture, field: str
    ) -> None:
        mock = mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=httpx.Response(400, json={"error": "authorization_pending"}),
        )
        requests.post(f"{test_server}/api/test/auth/v2/token", data={field: "DEV-1"})
        assert _sent_form(mock)["device_code"] == "DEV-1"


# ---------------------------------------------------------------------------
# Provider unavailable: 503 everywhere
# ---------------------------------------------------------------------------


class TestProviderUnavailable:
    @pytest.fixture
    def no_discovery(self, mocker: MockerFixture) -> None:
        mocker.patch.object(
            OIDCConfig, "oidc_overview", new_callable=PropertyMock, return_value={}
        )

    @pytest.mark.parametrize(
        ("method", "path", "data"),
        [
            ("GET", "login?redirect_uri=http://localhost:53100/callback", None),
            ("GET", "logout", None),
            ("POST", "device", None),
            ("POST", "token", {"refresh_token": "x"}),
            ("GET", "callback?code=c&state=s|http://localhost/cb|v", None),
        ],
    )
    def test_routes_answer_503(
        self,
        test_server: str,
        no_discovery: None,
        method: str,
        path: str,
        data: Optional[Dict[str, str]],
    ) -> None:
        res = requests.request(
            method,
            f"{test_server}/api/test/auth/v2/{path}",
            data=data,
            allow_redirects=False,
        )
        assert res.status_code == 503, res.text

    def test_unreachable_provider(
        self, test_server: str, mocker: MockerFixture
    ) -> None:
        mocker.patch(_MOCK_TARGET, side_effect=httpx.ConnectError("refused"))
        res = requests.post(
            f"{test_server}/api/test/auth/v2/token", data={"refresh_token": "x"}
        )
        assert res.status_code == 503

    def test_missing_endpoint_is_502(self, mocker: MockerFixture) -> None:
        mocker.patch.object(
            OIDCConfig,
            "oidc_overview",
            new_callable=PropertyMock,
            return_value={"issuer": "x"},
        )
        auth = OIDCAuth(client_id="c", discovery_url="http://idp/.well-known")
        with pytest.raises(InvalidRequest) as exc:
            auth._endpoint("device_authorization_endpoint")
        assert exc.value.status_code == 502


class TestDiscoveryErrors:
    """A broken discovery URL is not the same as a provider that is down."""

    @staticmethod
    async def _login_error(discovery_url: str) -> InvalidRequest:
        auth = OIDCAuth(client_id=CLIENT_ID, discovery_url=discovery_url)
        with pytest.raises(InvalidRequest) as exc:
            await auth.login(
                redirect_uri=CLIENT_CALLBACK,
                prompt="none",
                code_challenge=pkce_pair()[1],
            )
        return exc.value

    async def test_wrong_realm_is_502_with_reason(self) -> None:
        url = DISCOVERY_URL.replace("/.well-known/", "-no-such-realm/.well-known/")
        error = await self._login_error(url)
        assert error.status_code == 502
        assert "404" in error.detail and url in error.detail

    async def test_nobody_listening_is_503(self) -> None:
        port = _find_free_port()
        error = await self._login_error(
            f"http://127.0.0.1:{port}/.well-known/openid-configuration"
        )
        assert error.status_code == 503

    @pytest.mark.parametrize(
        ("response", "status"),
        [
            (httpx.Response(503, text="starting"), 503),
            (httpx.Response(200, text="<html>maintenance</html>"), 502),
        ],
    )
    async def test_answer_decides_status(
        self, mocker: MockerFixture, response: httpx.Response, status: int
    ) -> None:
        response.request = httpx.Request("GET", "http://idp.example.org/")
        mocker.patch("httpx.Client.get", return_value=response)
        error = await self._login_error("http://idp.example.org/.well-known/x")
        assert error.status_code == status

    async def test_logout_reports_it_too(self) -> None:
        url = DISCOVERY_URL.replace("/.well-known/", "-no-such-realm/.well-known/")
        auth = OIDCAuth(client_id=CLIENT_ID, discovery_url=url)
        with pytest.raises(InvalidRequest) as exc:
            await auth.logout(CLIENT_CALLBACK)
        assert exc.value.status_code == 502


# ---------------------------------------------------------------------------
# require_client_pkce
# ---------------------------------------------------------------------------


class TestRequireClientPKCE:
    @pytest.fixture
    def strict(self) -> OIDCAuth:
        return OIDCAuth(
            client_id=CLIENT_ID, discovery_url=DISCOVERY_URL, require_client_pkce=True
        )

    async def test_login_needs_challenge(self, strict: OIDCAuth) -> None:
        with pytest.raises(InvalidRequest) as exc:
            await strict.login(redirect_uri=CLIENT_CALLBACK, prompt="none")
        assert exc.value.status_code == 400
        url = await strict.login(
            redirect_uri=CLIENT_CALLBACK, prompt="none", code_challenge=pkce_pair()[1]
        )
        assert "code_challenge=" in url

    async def test_device_needs_challenge(self, strict: OIDCAuth) -> None:
        with pytest.raises(InvalidRequest) as exc:
            await strict.device_flow()
        assert exc.value.status_code == 400

    async def test_callback_is_disabled(self, strict: OIDCAuth) -> None:
        with pytest.raises(InvalidRequest) as exc:
            await strict.callback(code="c", state="s|http://localhost/cb|v")
        assert exc.value.status_code == 400

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"code": "c", "redirect_uri": CLIENT_CALLBACK},
            {"device_code": "d"},
            {"code": "c", "refresh_token": "r"},
        ],
    )
    async def test_redeeming_needs_verifier(
        self, strict: OIDCAuth, mocker: MockerFixture, kwargs: Dict[str, str]
    ) -> None:
        mock = mocker.patch(_MOCK_TARGET, new_callable=AsyncMock)
        with pytest.raises(InvalidRequest) as exc:
            await strict.token("/t", **kwargs)
        assert exc.value.status_code == 400
        assert "code_verifier" in exc.value.detail
        mock.assert_not_called()

    async def test_verifier_lets_the_code_through(
        self, strict: OIDCAuth, mocker: MockerFixture
    ) -> None:
        mock = mocker.patch(
            _MOCK_TARGET,
            new_callable=AsyncMock,
            return_value=httpx.Response(400, json={"error": "invalid_grant"}),
        )
        with pytest.raises(InvalidRequest):
            await strict.token(
                "/t", code="c", redirect_uri=CLIENT_CALLBACK, code_verifier="v"
            )
        assert _sent_form(mock)["code_verifier"] == "v"

    async def test_refresh_needs_no_verifier(
        self, strict: OIDCAuth, refresh_token: str
    ) -> None:
        token = await strict.token("/t", refresh_token=refresh_token)
        assert token.access_token

    async def test_refresh_wins_over_device_code(
        self, strict: OIDCAuth, refresh_token: str
    ) -> None:
        token = await strict.token(
            "/t", refresh_token=refresh_token, device_code="ignored"
        )
        assert token.access_token

    async def test_legacy_warning_is_logged_once(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        auth = OIDCAuth(client_id=CLIENT_ID, discovery_url=DISCOVERY_URL)
        with caplog.at_level("WARNING", logger="py_oidc_auth.auth_base"):
            await auth.login(redirect_uri=CLIENT_CALLBACK, prompt="none")
            await auth.login(redirect_uri=CLIENT_CALLBACK, prompt="none")
        assert sum("code_challenge" in r.getMessage() for r in caplog.records) == 1


async def test_garbled_provider_answer_is_502(mocker: MockerFixture) -> None:
    """Reachable but talking nonsense: that one is a bad gateway."""
    from py_oidc_auth.utils import oidc_request

    mocker.patch(
        _MOCK_TARGET,
        new_callable=AsyncMock,
        return_value=httpx.Response(200, text="<html>maintenance</html>"),
    )
    with pytest.raises(InvalidRequest) as exc:
        await oidc_request("http://idp.example.org/token", "POST")
    assert exc.value.status_code == 502
