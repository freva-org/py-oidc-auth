"""Integration tests for broker mode across all framework adapters.

These tests cover the broker code paths that the regular test_server fixtures
cannot reach, because those use passthrough (broker_mode=False) apps.

Strategy
--------
* Create an auth instance with ``broker_mode=True`` and an
  ``InMemoryBrokerStore`` so no real database is needed.
* Call ``_ensure_broker_ready()`` to initialise the broker, then use
  ``broker.mint()`` directly to produce valid broker JWTs — no IDP or
  Keycloak required.
* Hit protected endpoints with those JWTs and verify status codes.
* Hit token / JWKS endpoints using mocked IDP helpers.
* Cover remaining edge cases (RuntimeError branch, IntegrityError race).
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest

from py_oidc_auth.broker.issuer import GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ACCESS
from py_oidc_auth.broker.store import InMemoryBrokerStore, SQLAlchemyBrokerStore
from py_oidc_auth.schema import IDToken, Token


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_broker_auth(framework_cls: type, audience: str = "test-api") -> Any:
    store = InMemoryBrokerStore()
    return framework_cls(
        client_id="test",
        discovery_url="http://localhost/oidc",
        broker_mode=True,
        broker_store_obj=store,
        broker_audience=audience,
    )


def _get_broker_jwt(auth: Any, sub: str = "testuser", roles: list = None) -> str:
    """Sync — only call from non-async test functions."""
    broker = asyncio.run(auth._ensure_broker_ready())
    token, _ = broker.mint(sub=sub, email=f"{sub}@example.org", roles=roles or ["hpcuser"])
    return token


async def _get_broker_jwt_async(auth: Any, sub: str = "testuser", roles: list = None) -> str:
    """Async — use from @pytest.mark.asyncio tests."""
    broker = await auth._ensure_broker_ready()
    token, _ = broker.mint(sub=sub, email=f"{sub}@example.org", roles=roles or ["hpcuser"])
    return token


async def _get_expired_broker_jwt_async(auth: Any) -> str:
    broker = await auth._ensure_broker_ready()
    token, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
    return token


def _fake_idp_claims() -> IDToken:
    return IDToken(
        sub="janedoe",
        preferred_username="janedoe",
        email="janedoe@example.org",
        aud=["test"],
        realm_access={"roles": ["hpcuser"]},
    )


def _fake_idp_token() -> Token:
    now = int(time.time())
    return Token(
        access_token=pyjwt.encode(
            {"sub": "janedoe", "exp": now + 3600}, "secret"
        ),
        token_type="Bearer",
        expires=now + 3600,
        refresh_token="idp-refresh",
        refresh_expires=now + 7200,
        scope="openid profile email",
    )


# ---------------------------------------------------------------------------
# FastAPI — broker integration (sync TestClient)
# ---------------------------------------------------------------------------


class TestFastAPIBrokerIntegration:
    @pytest.fixture
    def broker_client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from py_oidc_auth import FastApiOIDCAuth

        auth = _make_broker_auth(FastApiOIDCAuth)
        app = FastAPI()
        # Use default paths: /auth/v2/token and /auth/v2/.well-known/jwks.json
        app.include_router(auth.create_auth_router(prefix="/api"))

        @app.get("/protected")
        async def protected(token: IDToken = auth.required()):
            return {"sub": token.sub}

        @app.get("/protected-bad-claims")
        async def protected_bad_claims(
            token: IDToken = auth.required(
                claims={"realm_access.roles": ["nonexistent"]}
            )
        ):
            return {"sub": token.sub}

        @app.get("/optional")
        async def optional_route(token: Optional[IDToken] = auth.optional()):
            return {"authenticated": token is not None}

        @app.get("/optional-claims")
        async def optional_claims(
            token: Optional[IDToken] = auth.optional(
                claims={"realm_access.roles": ["nonexistent"]}
            )
        ):
            return {"authenticated": token is not None}

        return TestClient(app, raise_server_exceptions=False), auth

    def test_required_valid_jwt(self, broker_client):
        client, auth = broker_client
        jwt = _get_broker_jwt(auth)
        res = client.get("/protected", headers={"Authorization": f"Bearer {jwt}"})
        assert res.status_code == 200
        assert res.json()["sub"] == "testuser"

    def test_required_expired_jwt(self, broker_client):
        client, auth = broker_client
        broker = asyncio.run(auth._ensure_broker_ready())
        jwt, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        assert client.get("/protected", headers={"Authorization": f"Bearer {jwt}"}).status_code == 401

    def test_required_invalid_jwt(self, broker_client):
        client, auth = broker_client
        assert client.get("/protected", headers={"Authorization": "Bearer garbage"}).status_code == 401

    def test_required_claims_pass(self, broker_client):
        client, auth = broker_client
        jwt = _get_broker_jwt(auth, roles=["hpcuser"])
        assert client.get("/protected", headers={"Authorization": f"Bearer {jwt}"}).status_code == 200

    def test_required_claims_fail(self, broker_client):
        client, auth = broker_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/protected-bad-claims", headers={"Authorization": f"Bearer {jwt}"}).status_code == 403

    def test_optional_valid_jwt(self, broker_client):
        client, auth = broker_client
        jwt = _get_broker_jwt(auth)
        res = client.get("/optional", headers={"Authorization": f"Bearer {jwt}"})
        assert res.status_code == 200
        assert res.json()["authenticated"] is True

    def test_optional_no_token(self, broker_client):
        client, auth = broker_client
        assert client.get("/optional").json()["authenticated"] is False

    def test_optional_expired_jwt(self, broker_client):
        client, auth = broker_client
        broker = asyncio.run(auth._ensure_broker_ready())
        jwt, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        assert client.get("/optional", headers={"Authorization": f"Bearer {jwt}"}).json()["authenticated"] is False

    def test_optional_invalid_jwt(self, broker_client):
        client, auth = broker_client
        assert client.get("/optional", headers={"Authorization": "Bearer junk"}).json()["authenticated"] is False

    def test_optional_claims_fail_returns_unauthenticated(self, broker_client):
        client, auth = broker_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/optional-claims", headers={"Authorization": f"Bearer {jwt}"}).json()["authenticated"] is False

    def test_jwks_endpoint(self, broker_client):
        client, auth = broker_client
        res = client.get("/api/auth/v2/.well-known/jwks.json")
        assert res.status_code == 200
        assert res.json()["keys"][0]["kty"] == "RSA"

    def test_broker_token_rfc8693_exchange(self, broker_client, mocker):
        client, auth = broker_client
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        mocker.patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe")
        res = client.post(
            "/api/auth/v2/token",
            data={
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "subject_token": "fake-idp-token",
                "subject_token_type": TOKEN_TYPE_ACCESS,
            },
        )
        assert res.status_code == 200
        assert "access_token" in res.json()

    def test_broker_token_refresh(self, broker_client, mocker):
        client, auth = broker_client
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        mocker.patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe")
        first = client.post(
            "/api/auth/v2/token",
            data={"grant_type": GRANT_TYPE_TOKEN_EXCHANGE, "subject_token": "fake-idp-token"},
        )
        assert first.status_code == 200
        broker_jwt = first.json()["access_token"]

        mocker.patch.object(auth, "token", new_callable=AsyncMock, return_value=_fake_idp_token())
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        res = client.post("/api/auth/v2/token", data={"refresh-token": broker_jwt})
        assert res.status_code == 200
        assert "access_token" in res.json()

    def test_broker_token_no_params_returns_error(self, broker_client):
        client, auth = broker_client
        res = client.post("/api/auth/v2/token", data={})
        assert res.status_code in (400, 401, 422)


# ---------------------------------------------------------------------------
# Flask — broker integration (sync test_client)
# ---------------------------------------------------------------------------


class TestFlaskBrokerIntegration:
    @pytest.fixture
    def broker_flask_client(self):
        from flask import Flask, jsonify
        from py_oidc_auth import FlaskOIDCAuth

        auth = _make_broker_auth(FlaskOIDCAuth)
        app = Flask(__name__)
        app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

        @app.get("/protected")
        @auth.required()
        def protected(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/protected-bad-claims")
        @auth.required(claims={"realm_access.roles": ["nonexistent"]})
        def protected_bad_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/optional")
        @auth.optional()
        def optional_route(token: Optional[IDToken]):
            return jsonify({"authenticated": token is not None})

        return app.test_client(), auth

    def test_required_valid_jwt(self, broker_flask_client):
        client, auth = broker_flask_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/protected", headers={"Authorization": f"Bearer {jwt}"}).status_code == 200

    def test_required_no_token(self, broker_flask_client):
        client, auth = broker_flask_client
        assert client.get("/protected").status_code == 401

    def test_required_expired_jwt(self, broker_flask_client):
        client, auth = broker_flask_client
        broker = asyncio.run(auth._ensure_broker_ready())
        jwt, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        assert client.get("/protected", headers={"Authorization": f"Bearer {jwt}"}).status_code == 401

    def test_required_invalid_jwt(self, broker_flask_client):
        client, auth = broker_flask_client
        assert client.get("/protected", headers={"Authorization": "Bearer bad"}).status_code == 401

    def test_required_claims_fail(self, broker_flask_client):
        client, auth = broker_flask_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/protected-bad-claims", headers={"Authorization": f"Bearer {jwt}"}).status_code == 403

    def test_optional_valid_jwt(self, broker_flask_client):
        client, auth = broker_flask_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/optional", headers={"Authorization": f"Bearer {jwt}"}).get_json()["authenticated"] is True

    def test_optional_no_token(self, broker_flask_client):
        client, auth = broker_flask_client
        assert client.get("/optional").get_json()["authenticated"] is False

    def test_optional_expired_jwt(self, broker_flask_client):
        client, auth = broker_flask_client
        broker = asyncio.run(auth._ensure_broker_ready())
        jwt, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        assert client.get("/optional", headers={"Authorization": f"Bearer {jwt}"}).get_json()["authenticated"] is False

    def test_optional_invalid_jwt(self, broker_flask_client):
        client, auth = broker_flask_client
        assert client.get("/optional", headers={"Authorization": "Bearer junk"}).get_json()["authenticated"] is False

    def test_jwks_endpoint(self, broker_flask_client):
        client, auth = broker_flask_client
        res = client.get("/api/auth/v2/.well-known/jwks.json")
        assert res.status_code == 200
        assert "keys" in res.get_json()

    def test_broker_token_exchange(self, broker_flask_client, mocker):
        client, auth = broker_flask_client
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        mocker.patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe")
        res = client.post(
            "/api/auth/v2/token",
            data={
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "subject_token": "fake-idp-token",
                "subject_token_type": TOKEN_TYPE_ACCESS,
            },
        )
        assert res.status_code == 200
        assert "access_token" in res.get_json()


# ---------------------------------------------------------------------------
# Quart — broker integration (async test_client)
# ---------------------------------------------------------------------------


class TestQuartBrokerIntegration:
    @pytest.fixture
    def broker_quart_app(self):
        from quart import Quart, jsonify
        from py_oidc_auth import QuartOIDCAuth

        auth = _make_broker_auth(QuartOIDCAuth)
        app = Quart(__name__)
        app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

        @app.get("/protected")
        @auth.required()
        async def protected(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/protected-bad-claims")
        @auth.required(claims={"realm_access.roles": ["nonexistent"]})
        async def protected_bad_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/optional")
        @auth.optional()
        async def optional_route(token: Optional[IDToken]):
            return jsonify({"authenticated": token is not None})

        return app, auth

    @pytest.mark.asyncio
    async def test_required_valid_jwt(self, broker_quart_app):
        app, auth = broker_quart_app
        jwt = await _get_broker_jwt_async(auth)
        async with app.test_client() as client:
            res = await client.get("/protected", headers={"Authorization": f"Bearer {jwt}"})
        assert res.status_code == 200

    @pytest.mark.asyncio
    async def test_required_no_token(self, broker_quart_app):
        app, auth = broker_quart_app
        async with app.test_client() as client:
            res = await client.get("/protected")
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_required_expired_jwt(self, broker_quart_app):
        app, auth = broker_quart_app
        jwt = await _get_expired_broker_jwt_async(auth)
        async with app.test_client() as client:
            res = await client.get("/protected", headers={"Authorization": f"Bearer {jwt}"})
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_required_invalid_jwt(self, broker_quart_app):
        app, auth = broker_quart_app
        async with app.test_client() as client:
            res = await client.get("/protected", headers={"Authorization": "Bearer bad"})
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_required_claims_fail(self, broker_quart_app):
        app, auth = broker_quart_app
        jwt = await _get_broker_jwt_async(auth)
        async with app.test_client() as client:
            res = await client.get("/protected-bad-claims", headers={"Authorization": f"Bearer {jwt}"})
        assert res.status_code == 403

    @pytest.mark.asyncio
    async def test_optional_valid_jwt(self, broker_quart_app):
        app, auth = broker_quart_app
        jwt = await _get_broker_jwt_async(auth)
        async with app.test_client() as client:
            res = await client.get("/optional", headers={"Authorization": f"Bearer {jwt}"})
        assert (await res.get_json())["authenticated"] is True

    @pytest.mark.asyncio
    async def test_optional_no_token(self, broker_quart_app):
        app, auth = broker_quart_app
        async with app.test_client() as client:
            res = await client.get("/optional")
        assert (await res.get_json())["authenticated"] is False

    @pytest.mark.asyncio
    async def test_optional_expired_jwt(self, broker_quart_app):
        app, auth = broker_quart_app
        jwt = await _get_expired_broker_jwt_async(auth)
        async with app.test_client() as client:
            res = await client.get("/optional", headers={"Authorization": f"Bearer {jwt}"})
        assert (await res.get_json())["authenticated"] is False

    @pytest.mark.asyncio
    async def test_optional_invalid_jwt(self, broker_quart_app):
        app, auth = broker_quart_app
        async with app.test_client() as client:
            res = await client.get("/optional", headers={"Authorization": "Bearer junk"})
        assert (await res.get_json())["authenticated"] is False

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self, broker_quart_app):
        app, auth = broker_quart_app
        async with app.test_client() as client:
            res = await client.get("/api/auth/v2/.well-known/jwks.json")
        assert res.status_code == 200
        assert "keys" in (await res.get_json())

    @pytest.mark.asyncio
    async def test_broker_token_exchange(self, broker_quart_app, mocker):
        app, auth = broker_quart_app
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        mocker.patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe")
        async with app.test_client() as client:
            res = await client.post(
                "/api/auth/v2/token",
                form={
                    "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                    "subject_token": "fake-idp-token",
                    "subject_token_type": TOKEN_TYPE_ACCESS,
                },
            )
        assert res.status_code == 200
        assert "access_token" in (await res.get_json())


# ---------------------------------------------------------------------------
# Litestar — broker integration (sync TestClient)
# ---------------------------------------------------------------------------


class TestLitestarBrokerIntegration:
    @pytest.fixture
    def broker_litestar_client(self):
        from litestar import Litestar, get
        from litestar.testing import TestClient as LitestarTestClient
        from py_oidc_auth import LitestarOIDCAuth

        auth = _make_broker_auth(LitestarOIDCAuth)

        @get("/protected", dependencies={"token": auth.required()})
        async def protected(token: IDToken) -> dict:
            return {"sub": token.sub}

        @get("/protected-bad-claims",
             dependencies={"token": auth.required(claims={"realm_access.roles": ["nonexistent"]})})
        async def protected_bad_claims(token: IDToken) -> dict:
            return {"sub": token.sub}

        @get("/optional", dependencies={"token": auth.optional()})
        async def optional_route(token: Optional[IDToken]) -> dict:
            return {"authenticated": token is not None}

        app = Litestar(
            route_handlers=[
                auth.create_auth_router(prefix="/api"),
                protected,
                protected_bad_claims,
                optional_route,
            ]
        )
        return LitestarTestClient(app=app, raise_server_exceptions=False), auth

    def test_required_valid_jwt(self, broker_litestar_client):
        client, auth = broker_litestar_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/protected", headers={"Authorization": f"Bearer {jwt}"}).status_code == 200

    def test_required_no_token(self, broker_litestar_client):
        client, auth = broker_litestar_client
        assert client.get("/protected").status_code in (401, 403)

    def test_required_expired_jwt(self, broker_litestar_client):
        client, auth = broker_litestar_client
        broker = asyncio.run(auth._ensure_broker_ready())
        jwt, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        assert client.get("/protected", headers={"Authorization": f"Bearer {jwt}"}).status_code == 401

    def test_required_invalid_jwt(self, broker_litestar_client):
        client, auth = broker_litestar_client
        assert client.get("/protected", headers={"Authorization": "Bearer garbage"}).status_code == 401

    def test_required_claims_fail(self, broker_litestar_client):
        client, auth = broker_litestar_client
        jwt = _get_broker_jwt(auth)
        assert client.get("/protected-bad-claims", headers={"Authorization": f"Bearer {jwt}"}).status_code in (401, 403)

    def test_optional_valid_jwt(self, broker_litestar_client):
        client, auth = broker_litestar_client
        jwt = _get_broker_jwt(auth)
        res = client.get("/optional", headers={"Authorization": f"Bearer {jwt}"})
        assert res.json()["authenticated"] is True

    def test_optional_no_token(self, broker_litestar_client):
        client, auth = broker_litestar_client
        assert client.get("/optional").json()["authenticated"] is False

    def test_optional_expired_jwt(self, broker_litestar_client):
        client, auth = broker_litestar_client
        broker = asyncio.run(auth._ensure_broker_ready())
        jwt, _ = broker.mint(sub="u", email=None, roles=[], expiry_seconds=-1)
        assert client.get("/optional", headers={"Authorization": f"Bearer {jwt}"}).json()["authenticated"] is False

    def test_optional_invalid_jwt(self, broker_litestar_client):
        client, auth = broker_litestar_client
        assert client.get("/optional", headers={"Authorization": "Bearer junk"}).json()["authenticated"] is False

    def test_jwks_endpoint(self, broker_litestar_client):
        client, auth = broker_litestar_client
        res = client.get("/api/auth/v2/.well-known/jwks.json")
        assert res.status_code == 200
        assert "keys" in res.json()

    def test_broker_token_exchange(self, broker_litestar_client, mocker):
        client, auth = broker_litestar_client
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        mocker.patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe")
        res = client.post(
            "/api/auth/v2/token",
            data={
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "subject_token": "fake-idp-token",
                "subject_token_type": TOKEN_TYPE_ACCESS,
            },
        )
        assert res.status_code == 200
        assert "access_token" in res.json()


# ---------------------------------------------------------------------------
# Django — broker integration (async AsyncClient)
# ---------------------------------------------------------------------------


class TestDjangoBrokerIntegration:
    @pytest.fixture
    def broker_django_auth(self):
        """Sync fixture — creates auth, view functions, and Django URL config.

        Returns ``(auth, protected_view, bad_claims_view, optional_view)`` so
        tests that send valid JWTs can call the view functions directly with
        ``RequestFactory``, bypassing Django's URL resolver cache entirely.
        URL routing is still configured for the JWKS / token-endpoint tests.
        """
        import django
        from django.conf import settings
        from django.http import HttpRequest, JsonResponse
        from py_oidc_auth import DjangoOIDCAuth

        auth = _make_broker_auth(DjangoOIDCAuth)

        @auth.required()
        async def protected(request: HttpRequest, token: IDToken) -> JsonResponse:
            return JsonResponse({"sub": token.sub})

        @auth.required(claims={"realm_access.roles": ["nonexistent"]})
        async def protected_bad_claims(request: HttpRequest, token: IDToken) -> JsonResponse:
            return JsonResponse({"sub": token.sub})

        @auth.optional()
        async def optional_route(request: HttpRequest, token: Optional[IDToken]) -> JsonResponse:
            return JsonResponse({"authenticated": token is not None})

        from django.urls import path
        urls_module = types.ModuleType("_broker_django_urls")
        urls_module.urlpatterns = [  # type: ignore[attr-defined]
            path("api/", __import__("django.urls", fromlist=["include"]).include(
                auth.get_urlpatterns()
            )),
            path("protected", protected),
            path("protected-bad-claims", protected_bad_claims),
            path("optional", optional_route),
        ]
        sys.modules["_broker_django_urls"] = urls_module

        if not settings.configured:
            settings.configure(
                DEBUG=True,
                SECRET_KEY="broker-test-key",
                ROOT_URLCONF="_broker_django_urls",
                ALLOWED_HOSTS=["*"],
            )
            django.setup()
        else:
            settings.ROOT_URLCONF = "_broker_django_urls"

        from django.urls import clear_url_caches
        clear_url_caches()

        return auth, protected, protected_bad_claims, optional_route

    @staticmethod
    def _make_request(method: str = "GET", bearer: str = "") -> Any:
        """Build a Django HttpRequest with an Authorization header."""
        from django.test import RequestFactory
        factory = RequestFactory()
        kwargs = {}
        if bearer:
            kwargs["HTTP_AUTHORIZATION"] = f"Bearer {bearer}"
        return getattr(factory, method.lower())("/", **kwargs)

    @pytest.mark.asyncio
    async def test_required_valid_jwt(self, broker_django_auth):
        auth, protected, _, _ = broker_django_auth
        jwt = await _get_broker_jwt_async(auth)
        res = await protected(self._make_request(bearer=jwt))
        assert res.status_code == 200
        assert json.loads(res.content)["sub"] == "testuser"

    @pytest.mark.asyncio
    async def test_required_no_token(self, broker_django_auth):
        _, protected, _, _ = broker_django_auth
        res = await protected(self._make_request())
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_required_expired_jwt(self, broker_django_auth):
        auth, protected, _, _ = broker_django_auth
        jwt = await _get_expired_broker_jwt_async(auth)
        res = await protected(self._make_request(bearer=jwt))
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_required_invalid_jwt(self, broker_django_auth):
        _, protected, _, _ = broker_django_auth
        res = await protected(self._make_request(bearer="garbage"))
        assert res.status_code == 401

    @pytest.mark.asyncio
    async def test_required_claims_fail(self, broker_django_auth):
        auth, _, bad_claims, _ = broker_django_auth
        jwt = await _get_broker_jwt_async(auth)
        res = await bad_claims(self._make_request(bearer=jwt))
        assert res.status_code == 403

    @pytest.mark.asyncio
    async def test_optional_valid_jwt(self, broker_django_auth):
        auth, _, _, optional = broker_django_auth
        jwt = await _get_broker_jwt_async(auth)
        res = await optional(self._make_request(bearer=jwt))
        assert json.loads(res.content)["authenticated"] is True

    @pytest.mark.asyncio
    async def test_optional_no_token(self, broker_django_auth):
        _, _, _, optional = broker_django_auth
        res = await optional(self._make_request())
        assert json.loads(res.content)["authenticated"] is False

    @pytest.mark.asyncio
    async def test_optional_expired_jwt(self, broker_django_auth):
        auth, _, _, optional = broker_django_auth
        jwt = await _get_expired_broker_jwt_async(auth)
        res = await optional(self._make_request(bearer=jwt))
        assert json.loads(res.content)["authenticated"] is False

    @pytest.mark.asyncio
    async def test_optional_invalid_jwt(self, broker_django_auth):
        _, _, _, optional = broker_django_auth
        res = await optional(self._make_request(bearer="junk"))
        assert json.loads(res.content)["authenticated"] is False

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self, broker_django_auth):
        from django.test import AsyncClient
        res = await AsyncClient().get("/api/auth/v2/.well-known/jwks.json")
        assert res.status_code == 200
        assert "keys" in json.loads(res.content)

    @pytest.mark.asyncio
    async def test_broker_token_exchange(self, broker_django_auth, mocker):
        from django.test import AsyncClient
        auth, _, _, _ = broker_django_auth
        mocker.patch.object(auth, "_get_token", new_callable=AsyncMock, return_value=_fake_idp_claims())
        mocker.patch("py_oidc_auth.auth_base.get_username", new_callable=AsyncMock, return_value="janedoe")
        res = await AsyncClient().post(
            "/api/auth/v2/token",
            data={
                "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
                "subject_token": "fake-idp-token",
                "subject_token_type": TOKEN_TYPE_ACCESS,
            },
        )
        assert res.status_code == 200
        assert "access_token" in json.loads(res.content)


# ---------------------------------------------------------------------------
# Tornado — broker integration (async HTTP test)
# ---------------------------------------------------------------------------


class TestTornadoBrokerIntegration:
    @pytest.fixture
    def broker_tornado_app(self):
        import tornado.web
        from py_oidc_auth import TornadoOIDCAuth

        auth = _make_broker_auth(TornadoOIDCAuth)

        class ProtectedHandler(tornado.web.RequestHandler):
            @auth.required()
            async def get(self, token: IDToken) -> None:
                self.set_header("Content-Type", "application/json")
                self.write(json.dumps({"sub": token.sub}))

        class ProtectedBadClaimsHandler(tornado.web.RequestHandler):
            @auth.required(claims={"realm_access.roles": ["nonexistent"]})
            async def get(self, token: IDToken) -> None:
                self.set_header("Content-Type", "application/json")
                self.write(json.dumps({"sub": token.sub}))

        class OptionalHandler(tornado.web.RequestHandler):
            @auth.optional()
            async def get(self, token: Optional[IDToken]) -> None:
                self.set_header("Content-Type", "application/json")
                self.write(json.dumps({"authenticated": token is not None}))

        app = tornado.web.Application(
            auth.get_auth_routes(prefix="/api")
            + [
                (r"/protected", ProtectedHandler),
                (r"/protected-bad-claims", ProtectedBadClaimsHandler),
                (r"/optional", OptionalHandler),
            ]
        )
        return app, auth

    async def _fetch(self, app: Any, path: str, *, headers: dict = None) -> Any:
        import tornado.httpserver
        import tornado.testing
        sock, port = tornado.testing.bind_unused_port()
        server = tornado.httpserver.HTTPServer(app)
        server.add_sockets([sock])
        client = tornado.testing.AsyncHTTPClient()
        try:
            res = await client.fetch(
                f"http://localhost:{port}{path}",
                headers=headers or {},
                raise_error=False,
            )
        finally:
            server.stop()
        return res

    @pytest.mark.asyncio
    async def test_required_valid_jwt(self, broker_tornado_app):
        app, auth = broker_tornado_app
        jwt = await _get_broker_jwt_async(auth)
        res = await self._fetch(app, "/protected", headers={"Authorization": f"Bearer {jwt}"})
        assert res.code == 200

    @pytest.mark.asyncio
    async def test_required_no_token(self, broker_tornado_app):
        app, auth = broker_tornado_app
        assert (await self._fetch(app, "/protected")).code == 401

    @pytest.mark.asyncio
    async def test_required_expired_jwt(self, broker_tornado_app):
        app, auth = broker_tornado_app
        jwt = await _get_expired_broker_jwt_async(auth)
        assert (await self._fetch(app, "/protected", headers={"Authorization": f"Bearer {jwt}"})).code == 401

    @pytest.mark.asyncio
    async def test_required_invalid_jwt(self, broker_tornado_app):
        app, auth = broker_tornado_app
        assert (await self._fetch(app, "/protected", headers={"Authorization": "Bearer garbage"})).code == 401

    @pytest.mark.asyncio
    async def test_required_claims_fail(self, broker_tornado_app):
        app, auth = broker_tornado_app
        jwt = await _get_broker_jwt_async(auth)
        assert (await self._fetch(app, "/protected-bad-claims", headers={"Authorization": f"Bearer {jwt}"})).code == 403

    @pytest.mark.asyncio
    async def test_optional_valid_jwt(self, broker_tornado_app):
        app, auth = broker_tornado_app
        jwt = await _get_broker_jwt_async(auth)
        res = await self._fetch(app, "/optional", headers={"Authorization": f"Bearer {jwt}"})
        assert json.loads(res.body)["authenticated"] is True

    @pytest.mark.asyncio
    async def test_optional_no_token(self, broker_tornado_app):
        app, auth = broker_tornado_app
        assert json.loads((await self._fetch(app, "/optional")).body)["authenticated"] is False

    @pytest.mark.asyncio
    async def test_optional_expired_jwt(self, broker_tornado_app):
        app, auth = broker_tornado_app
        jwt = await _get_expired_broker_jwt_async(auth)
        assert json.loads((await self._fetch(app, "/optional", headers={"Authorization": f"Bearer {jwt}"})).body)["authenticated"] is False

    @pytest.mark.asyncio
    async def test_optional_invalid_jwt(self, broker_tornado_app):
        app, auth = broker_tornado_app
        assert json.loads((await self._fetch(app, "/optional", headers={"Authorization": "Bearer junk"})).body)["authenticated"] is False

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self, broker_tornado_app):
        app, auth = broker_tornado_app
        res = await self._fetch(app, "/api/auth/v2/.well-known/jwks.json")
        assert res.code == 200
        assert "keys" in json.loads(res.body)


# ---------------------------------------------------------------------------
# issuer.py — RuntimeError branch (no running loop during lazy refresh)
# ---------------------------------------------------------------------------


class TestLazyRefreshNoRunningLoop:
    def test_no_running_loop_is_silently_ignored(self) -> None:
        """RuntimeError from asyncio.get_running_loop() is caught silently."""
        from py_oidc_auth.broker.issuer import TokenBroker

        store = InMemoryBrokerStore()
        broker = TokenBroker(
            store=store,
            issuer="https://local.example.org",
            audience="test-api",
            trusted_issuers=["https://peer.example.org"],
        )
        broker._ready = True
        broker._peer_last_refresh.pop("https://peer.example.org", None)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"keys": []}

        # Called from a sync (non-async) context — no running event loop.
        # The except RuntimeError: pass branch must be hit without raising.
        with patch("py_oidc_auth.broker.issuer.httpx.get", return_value=mock_resp):
            broker._maybe_refresh_peer_keys_for("unknown-kid")  # must not raise


# ---------------------------------------------------------------------------
# store.py — IntegrityError race in load_or_create_signing_key
# ---------------------------------------------------------------------------


class TestSQLAlchemySigningKeyRace:
    @pytest.mark.asyncio
    async def test_concurrent_key_creation_returns_same_key(self, tmp_path: Any) -> None:
        """Two stores on the same DB racing to insert the signing key.

        One INSERT wins; the other hits IntegrityError (the
        ``except IntegrityError: pass`` branch) and re-reads the winner's
        key.  Both must end up with the same PEM.
        """
        url = f"sqlite+aiosqlite:///{tmp_path}/race.sqlite"

        # Two independent engines pointing at the same SQLite file
        store1 = SQLAlchemyBrokerStore(url=url)
        store2 = SQLAlchemyBrokerStore(url=url)
        await store1.setup()
        await store2.setup()

        # Run concurrently — asyncio interleaves at await points so both
        # stores will see "key not found" on their initial SELECT, then race
        # on INSERT.  The loser hits IntegrityError → pass → re-reads key.
        results = await asyncio.gather(
            store1.load_or_create_signing_key(),
            store2.load_or_create_signing_key(),
        )
        assert results[0] == results[1]
