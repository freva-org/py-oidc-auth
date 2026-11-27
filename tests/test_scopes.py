"""Scopes: what clients may ask for at login, and scopes in broker mode.

* ``/login?scope=...`` may only narrow the configured scopes (plus
  ``openid``, ``offline_access`` and ``allowed_scopes``).
* Broker JWTs carry the scope the identity provider granted.
* ``required(scopes=...)`` / ``optional(scopes=...)`` are enforced in broker
  mode by every framework adapter.

No identity provider is needed: broker JWTs are minted directly.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from typing import Any, Optional
from unittest.mock import AsyncMock, patch

import pytest

from py_oidc_auth import FastApiOIDCAuth
from py_oidc_auth.broker.store import InMemoryBrokerStore
from py_oidc_auth.exceptions import InvalidRequest
from py_oidc_auth.schema import IDToken, Token

try:  # Litestar resolves handler annotations in this module's namespace.
    from litestar.di import NamedDependency  # noqa: F401
except ImportError:  # pragma: no cover
    pass

SCOPED = "openid profile data:read"


def _auth(cls: type = FastApiOIDCAuth, **kwargs: Any) -> Any:
    kwargs.setdefault("scopes", "openid profile email")
    return cls(
        client_id="test",
        discovery_url="http://localhost/oidc",
        broker_mode=True,
        broker_store_obj=InMemoryBrokerStore(),
        broker_audience="test-api",
        **kwargs,
    )


async def _jwt(auth: Any, scope: Optional[str]) -> str:
    broker = await auth._ensure_broker_ready()
    token, _ = broker.mint(sub="u", email=None, roles=[], scope=scope)
    return token


def _jwt_sync(auth: Any, scope: Optional[str]) -> str:
    return asyncio.run(_jwt(auth, scope))


# ---------------------------------------------------------------------------
# What a client may ask for at login
# ---------------------------------------------------------------------------


class TestRequestedScopes:
    def test_default_is_the_configured_scopes(self) -> None:
        auth = _auth()
        assert auth.requested_scopes(None) == ["openid", "profile", "email"]
        assert auth.requested_scopes("  ") == ["openid", "profile", "email"]

    def test_narrowing_is_allowed(self) -> None:
        assert _auth().requested_scopes("openid email") == ["openid", "email"]

    def test_openid_and_offline_access_are_always_allowed(self) -> None:
        auth = _auth(scopes="profile")
        assert auth.requested_scopes("openid offline_access") == [
            "openid",
            "offline_access",
        ]

    def test_other_scopes_are_refused(self) -> None:
        with pytest.raises(InvalidRequest) as exc_info:
            _auth().requested_scopes("openid admin roles")
        assert exc_info.value.status_code == 400
        assert "invalid_scope" in exc_info.value.detail
        assert "admin roles" in exc_info.value.detail

    def test_allowed_scopes_extend_the_list(self) -> None:
        auth = _auth(allowed_scopes="data:read data:write")
        assert auth.requested_scopes("openid data:read") == ["openid", "data:read"]
        with pytest.raises(InvalidRequest):
            auth.requested_scopes("data:admin")

    @pytest.mark.asyncio
    async def test_login_refuses_before_contacting_the_provider(self) -> None:
        auth = _auth()
        with patch.object(auth, "_ensure_auth_initialized", AsyncMock()) as init:
            with pytest.raises(InvalidRequest) as exc_info:
                await auth.login(
                    redirect_uri="http://localhost:53100/callback",
                    prompt="none",
                    scope="openid admin",
                    code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    code_challenge_method="S256",
                )
        assert exc_info.value.status_code == 400
        init.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_login_sends_the_narrowed_scopes(self) -> None:
        auth = _auth()
        with patch.object(auth, "_ensure_auth_initialized", AsyncMock()):
            with patch.object(
                auth, "_endpoint", return_value="https://idp.example.org/auth"
            ):
                url = await auth.login(
                    redirect_uri="http://localhost:53100/callback",
                    prompt="none",
                    offline_access=False,
                    scope="email",
                    code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    code_challenge_method="S256",
                )
        assert "scope=email+openid&" in url


# ---------------------------------------------------------------------------
# Broker JWTs carry the granted scope
# ---------------------------------------------------------------------------


class TestBrokerScopeClaim:
    @pytest.mark.asyncio
    async def test_mint_with_and_without_scope(self) -> None:
        auth = _auth()
        broker = await auth._ensure_broker_ready()
        with_scope, _ = broker.mint(sub="u", email=None, roles=[], scope=SCOPED)
        without, _ = broker.mint(sub="u", email=None, roles=[])
        assert broker.verify(with_scope).scope == SCOPED
        assert broker.verify(without).scope is None

    @pytest.mark.asyncio
    async def test_login_session_gets_the_idp_scope(self) -> None:
        auth = _auth()
        idp_token = Token(
            access_token="idp-access",
            token_type="Bearer",
            expires=2_000_000_000,
            refresh_token="idp-refresh",
            refresh_expires=2_000_000_000,
            scope=SCOPED,
        )
        claims = IDToken(sub="jane", preferred_username="jane", email=None)
        with patch.object(auth, "_get_token", AsyncMock(return_value=claims)):
            with patch.object(auth, "make_oidc_request", AsyncMock(return_value={})):
                token = await auth.mint_and_store(idp_token)
        broker = await auth._ensure_broker_ready()
        assert broker.verify(token.access_token).scope == SCOPED

    @pytest.mark.asyncio
    async def test_exchange_gets_the_subject_scope(self) -> None:
        auth = _auth()
        claims = IDToken(sub="jane", preferred_username="jane", scope=SCOPED)
        with patch.object(auth, "_get_token", AsyncMock(return_value=claims)):
            token = await auth.broker_exchange("idp-access")
        broker = await auth._ensure_broker_ready()
        assert broker.verify(token.access_token).scope == SCOPED

    def test_missing_scopes(self) -> None:
        token = IDToken(sub="u", scope="openid data:read")
        assert FastApiOIDCAuth._missing_scopes(token, ["data:read"]) == []
        assert FastApiOIDCAuth._missing_scopes(token, ["b", "a"]) == ["a", "b"]
        assert FastApiOIDCAuth._missing_scopes(IDToken(sub="u"), ["a"]) == ["a"]
        assert FastApiOIDCAuth._missing_scopes(IDToken(sub="u"), []) == []


# ---------------------------------------------------------------------------
# Every adapter enforces scopes in broker mode
# ---------------------------------------------------------------------------


class TestFastAPI:
    @pytest.fixture
    def client(self) -> Any:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        auth = _auth()
        app = FastAPI()

        @app.get("/need")
        async def need(token: IDToken = auth.required(scopes="data:read")) -> dict:
            return {"sub": token.sub}

        @app.get("/maybe")
        async def maybe(
            token: Optional[IDToken] = auth.optional(scopes="data:read"),
        ) -> dict:
            return {"authenticated": token is not None}

        @app.get("/any")
        async def any_(token: IDToken = auth.required()) -> dict:
            return {"sub": token.sub}

        return TestClient(app, raise_server_exceptions=False), auth

    def test_scoped_token(self, client: Any) -> None:
        c, auth = client
        headers = {"Authorization": f"Bearer {_jwt_sync(auth, SCOPED)}"}
        assert c.get("/need", headers=headers).status_code == 200
        assert c.get("/maybe", headers=headers).json()["authenticated"] is True

    def test_token_without_the_scope(self, client: Any) -> None:
        c, auth = client
        headers = {"Authorization": f"Bearer {_jwt_sync(auth, 'openid')}"}
        res = c.get("/need", headers=headers)
        assert res.status_code == 403
        assert "data:read" in res.json()["detail"]
        assert c.get("/maybe", headers=headers).json()["authenticated"] is False

    def test_old_token_without_scope_claim(self, client: Any) -> None:
        """Tokens from before this change pass where no scope is needed."""
        c, auth = client
        headers = {"Authorization": f"Bearer {_jwt_sync(auth, None)}"}
        assert c.get("/any", headers=headers).status_code == 200
        assert c.get("/need", headers=headers).status_code == 403


class TestFlask:
    @pytest.fixture
    def client(self) -> Any:
        from flask import Flask, jsonify

        from py_oidc_auth import FlaskOIDCAuth

        auth = _auth(FlaskOIDCAuth)
        app = Flask(__name__)

        @app.get("/need")
        @auth.required(scopes="data:read")
        def need(token: IDToken) -> Any:
            return jsonify({"sub": token.sub})

        @app.get("/maybe")
        @auth.optional(scopes="data:read")
        def maybe(token: Optional[IDToken]) -> Any:
            return jsonify({"authenticated": token is not None})

        return app.test_client(), auth

    def test_scopes(self, client: Any) -> None:
        c, auth = client
        ok = {"Authorization": f"Bearer {_jwt_sync(auth, SCOPED)}"}
        bad = {"Authorization": f"Bearer {_jwt_sync(auth, 'openid')}"}
        assert c.get("/need", headers=ok).status_code == 200
        res = c.get("/need", headers=bad)
        assert res.status_code == 403
        assert b"data:read" in res.data
        assert c.get("/maybe", headers=ok).get_json()["authenticated"] is True
        assert c.get("/maybe", headers=bad).get_json()["authenticated"] is False


class TestQuart:
    @pytest.fixture
    def app(self) -> Any:
        from quart import Quart, jsonify

        from py_oidc_auth import QuartOIDCAuth

        auth = _auth(QuartOIDCAuth)
        app = Quart(__name__)

        @app.get("/need")
        @auth.required(scopes="data:read")
        async def need(token: IDToken) -> Any:
            return jsonify({"sub": token.sub})

        @app.get("/maybe")
        @auth.optional(scopes="data:read")
        async def maybe(token: Optional[IDToken]) -> Any:
            return jsonify({"authenticated": token is not None})

        return app, auth

    @pytest.mark.asyncio
    async def test_scopes(self, app: Any) -> None:
        quart_app, auth = app
        ok = {"Authorization": f"Bearer {await _jwt(auth, SCOPED)}"}
        bad = {"Authorization": f"Bearer {await _jwt(auth, 'openid')}"}
        async with quart_app.test_client() as c:
            assert (await c.get("/need", headers=ok)).status_code == 200
            assert (await c.get("/need", headers=bad)).status_code == 403
            res = await c.get("/maybe", headers=ok)
            assert (await res.get_json())["authenticated"] is True
            res = await c.get("/maybe", headers=bad)
            assert (await res.get_json())["authenticated"] is False


class TestLitestar:
    @pytest.fixture
    def client(self) -> Any:
        from litestar import Litestar, get
        from litestar.testing import TestClient

        from py_oidc_auth import LitestarOIDCAuth

        auth = _auth(LitestarOIDCAuth)

        @get("/need", dependencies={"token": auth.required(scopes="data:read")})
        async def need(token: NamedDependency[IDToken]) -> dict:
            return {"sub": token.sub}

        @get("/maybe", dependencies={"token": auth.optional(scopes="data:read")})
        async def maybe(token: NamedDependency[Optional[IDToken]]) -> dict:
            return {"authenticated": token is not None}

        app = Litestar(route_handlers=[need, maybe])
        return TestClient(app=app, raise_server_exceptions=False), auth

    def test_scopes(self, client: Any) -> None:
        c, auth = client
        ok = {"Authorization": f"Bearer {_jwt_sync(auth, SCOPED)}"}
        bad = {"Authorization": f"Bearer {_jwt_sync(auth, 'openid')}"}
        with c:
            assert c.get("/need", headers=ok).status_code == 200
            res = c.get("/need", headers=bad)
            assert res.status_code == 403
            assert "data:read" in res.text
            assert c.get("/maybe", headers=ok).json()["authenticated"] is True
            assert c.get("/maybe", headers=bad).json()["authenticated"] is False


class TestDjango:
    @pytest.fixture
    def views(self) -> Any:
        import django
        from django.conf import settings
        from django.http import HttpRequest, JsonResponse

        from py_oidc_auth import DjangoOIDCAuth

        auth = _auth(DjangoOIDCAuth)

        @auth.required(scopes="data:read")
        async def need(request: HttpRequest, token: IDToken) -> JsonResponse:
            return JsonResponse({"sub": token.sub})

        @auth.optional(scopes="data:read")
        async def maybe(request: HttpRequest, token: Optional[IDToken]) -> JsonResponse:
            return JsonResponse({"authenticated": token is not None})

        if not settings.configured:
            urls = types.ModuleType("_scopes_django_urls")
            urls.urlpatterns = []  # type: ignore[attr-defined]
            sys.modules["_scopes_django_urls"] = urls
            settings.configure(
                DEBUG=True,
                SECRET_KEY="scopes-test-key",
                ROOT_URLCONF="_scopes_django_urls",
                ALLOWED_HOSTS=["*"],
            )
            django.setup()
        return auth, need, maybe

    @staticmethod
    def _request(bearer: str) -> Any:
        from django.test import RequestFactory

        return RequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {bearer}")

    @pytest.mark.asyncio
    async def test_scopes(self, views: Any) -> None:
        auth, need, maybe = views
        ok, bad = await _jwt(auth, SCOPED), await _jwt(auth, "openid")
        assert (await need(self._request(ok))).status_code == 200
        res = await need(self._request(bad))
        assert res.status_code == 403
        assert b"data:read" in res.content
        assert json.loads((await maybe(self._request(ok))).content)["authenticated"]
        assert not json.loads((await maybe(self._request(bad))).content)[
            "authenticated"
        ]


class TestTornado:
    @pytest.fixture
    def app(self) -> Any:
        import tornado.web

        from py_oidc_auth import TornadoOIDCAuth

        auth = _auth(TornadoOIDCAuth)

        class Need(tornado.web.RequestHandler):
            @auth.required(scopes="data:read")
            async def get(self, token: IDToken) -> None:
                self.write(json.dumps({"sub": token.sub}))

        class Maybe(tornado.web.RequestHandler):
            @auth.optional(scopes="data:read")
            async def get(self, token: Optional[IDToken]) -> None:
                self.write(json.dumps({"authenticated": token is not None}))

        return tornado.web.Application([(r"/need", Need), (r"/maybe", Maybe)]), auth

    @staticmethod
    async def _get(app: Any, path: str, bearer: str) -> Any:
        import tornado.httpserver
        import tornado.testing

        sock, port = tornado.testing.bind_unused_port()
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets([sock])
        try:
            return await tornado.testing.AsyncHTTPClient().fetch(
                f"http://localhost:{port}{path}",
                headers={"Authorization": f"Bearer {bearer}"},
                raise_error=False,
            )
        finally:
            server.stop()

    @pytest.mark.asyncio
    async def test_scopes(self, app: Any) -> None:
        tornado_app, auth = app
        ok, bad = await _jwt(auth, SCOPED), await _jwt(auth, "openid")
        assert (await self._get(tornado_app, "/need", ok)).code == 200
        res = await self._get(tornado_app, "/need", bad)
        assert res.code == 403
        assert b"data:read" in res.body
        res = await self._get(tornado_app, "/maybe", ok)
        assert json.loads(res.body)["authenticated"] is True
        res = await self._get(tornado_app, "/maybe", bad)
        assert json.loads(res.body)["authenticated"] is False
