"""Pytest configuration for py-oidc-auth tests.

Expects a running Keycloak instance. Configure via environment variables:

    OIDC_DISCOVERY_URL  (default: http://localhost:8080/realms/freva/.well-known/openid-configuration)
    OIDC_CLIENT_ID      (default: freva)
    OIDC_CLIENT_SECRET  (default: "")
    OIDC_TEST_USER      (default: janedoe)
    OIDC_TEST_PASSWORD  (default: janedoe123)

The ``test_server`` fixture is parametrized over all installed backends.
Every test that uses it runs against each backend automatically::

    test_routes.py::TestLoginRoute::test_login_redirects[fastapi]   PASSED
    test_routes.py::TestLoginRoute::test_login_redirects[flask]     PASSED
    test_routes.py::TestLoginRoute::test_login_redirects[quart]     PASSED
    test_routes.py::TestLoginRoute::test_login_redirects[tornado]   PASSED
    test_routes.py::TestLoginRoute::test_login_redirects[litestar]  PASSED
    test_routes.py::TestLoginRoute::test_login_redirects[django]    PASSED
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time
import types
from typing import Any, Callable, Dict, Iterator, Optional

import pytest
import requests

from py_oidc_auth import IDToken, OIDCAuth
from py_oidc_auth.utils import OIDCConfig

# ---------------------------------------------------------------------------
# Environment-based configuration
# ---------------------------------------------------------------------------

DISCOVERY_URL = os.getenv(
    "OIDC_DISCOVERY_URL",
    "http://localhost:8080/realms/freva/.well-known/openid-configuration",
)
CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "freva")
CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
TEST_USER = os.getenv("OIDC_TEST_USER", "janedoe")
TEST_PASSWORD = os.getenv("OIDC_TEST_PASSWORD", "janedoe123")

Required: Any = Ellipsis


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _get_token_via_password_grant(
    discovery_url: str = DISCOVERY_URL,
    client_id: str = CLIENT_ID,
    client_secret: str = CLIENT_SECRET,
    username: str = TEST_USER,
    password: str = TEST_PASSWORD,
) -> Dict[str, Any]:
    """Obtain a real token from Keycloak using the resource-owner password grant."""
    disc = requests.get(discovery_url, timeout=5).json()
    data: Dict[str, str] = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    }
    if client_secret:
        data["client_secret"] = client_secret
    resp = requests.post(
        disc["token_endpoint"],
        data={k: v for k, v in data.items() if v},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _wait_for_server(base_url: str, timeout: float = 10) -> None:
    """Poll until the server responds on any path."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            requests.get(base_url, timeout=0.5)
            return
        except requests.ConnectionError:
            time.sleep(0.2)
    raise RuntimeError(f"Server at {base_url} did not start in time")


def _make_auth_kwargs(auth: OIDCAuth) -> Dict[str, Any]:
    """Extract constructor kwargs from an existing OIDCAuth instance."""
    return dict(
        client_id=auth.config.client_id,
        discovery_url=auth.config.discovery_url,
        client_secret=auth.config.client_secret,
        scopes=" ".join(auth.config.scopes or []),
        proxy=auth.config.proxy,
        claims=auth.config.claims,
    )


# =========================================================================
# App factories — each returns a ready-to-serve app
# =========================================================================


def _create_fastapi_app(auth: OIDCAuth) -> Any:
    from fastapi import FastAPI

    from py_oidc_auth import FastApiOIDCAuth

    fa = FastApiOIDCAuth(**_make_auth_kwargs(auth))
    app = FastAPI()
    app.include_router(fa.create_auth_router(prefix="/api/test"))

    @app.get("/protected")
    async def protected(token: IDToken = fa.required()):
        return {"sub": token.sub, "preferred_username": token.preferred_username}

    @app.get("/protected-claims")
    async def protected_claims(
        token: IDToken = fa.required(
            claims={"realm_access.roles": ["offline_access"]},
        ),
    ):
        return {"sub": token.sub}

    @app.get("/protected-bad-claims")
    async def protected_bad_claims(
        token: IDToken = fa.required(
            claims={"realm_access.roles": ["nonexistent-role"]},
        ),
    ):
        return {"sub": token.sub}

    @app.get("/optional")
    async def optional_auth(token: Optional[IDToken] = fa.optional()):
        if token:
            return {"authenticated": True, "sub": token.sub}
        return {"authenticated": False}

    @app.get("/scoped-valid")
    async def scoped_valid(
        token: IDToken = fa.required(scopes="profile email"),
    ):
        return {"sub": token.sub, "scope": token.scope}

    @app.get("/scoped-single")
    async def scoped_single(token: IDToken = fa.required(scopes="profile")):
        return {"sub": token.sub}

    @app.get("/scoped-bad")
    async def scoped_bad(
        token: IDToken = fa.required(scopes="admin superuser"),
    ):
        return {"sub": token.sub}

    @app.get("/scoped-partial")
    async def scoped_partial(
        token: IDToken = fa.required(scopes="profile nonexistent-scope"),
    ):
        return {"sub": token.sub}

    @app.get("/scoped-and-claims")
    async def scoped_and_claims(
        token: IDToken = fa.required(
            scopes="profile",
            claims={"realm_access.roles": ["offline_access"]},
        ),
    ):
        return {"sub": token.sub}

    @app.get("/scoped-ok-claims-bad")
    async def scoped_ok_claims_bad(
        token: IDToken = fa.required(
            scopes="profile",
            claims={"realm_access.roles": ["nonexistent-role"]},
        ),
    ):
        return {"sub": token.sub}

    @app.get("/scoped-bad-claims-ok")
    async def scoped_bad_claims_ok(
        token: IDToken = fa.required(
            scopes="impossible-scope",
            claims={"realm_access.roles": ["offline_access"]},
        ),
    ):
        return {"sub": token.sub}

    return app


def _flask_endpoints(fl_auth: Any) -> Callable:
    """Register test endpoints on a Flask app — shared between Flask factories."""
    from flask import jsonify

    def register(app: Any) -> None:
        @app.get("/protected")
        @fl_auth.required()
        def protected(token: IDToken):
            return jsonify(
                {"sub": token.sub, "preferred_username": token.preferred_username}
            )

        @app.get("/protected-claims")
        @fl_auth.required(claims={"realm_access.roles": ["offline_access"]})
        def protected_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/protected-bad-claims")
        @fl_auth.required(claims={"realm_access.roles": ["nonexistent-role"]})
        def protected_bad_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/optional")
        @fl_auth.optional()
        def optional_auth(token: Optional[IDToken]):
            if token:
                return jsonify({"authenticated": True, "sub": token.sub})
            return jsonify({"authenticated": False})

        @app.get("/scoped-valid")
        @fl_auth.required(scopes="profile email")
        def scoped_valid(token: IDToken):
            return jsonify({"sub": token.sub, "scope": token.scope})

        @app.get("/scoped-single")
        @fl_auth.required(scopes="profile")
        def scoped_single(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-bad")
        @fl_auth.required(scopes="admin superuser")
        def scoped_bad(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-partial")
        @fl_auth.required(scopes="profile nonexistent-scope")
        def scoped_partial(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-and-claims")
        @fl_auth.required(
            scopes="profile",
            claims={"realm_access.roles": ["offline_access"]},
        )
        def scoped_and_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-ok-claims-bad")
        @fl_auth.required(
            scopes="profile",
            claims={"realm_access.roles": ["nonexistent-role"]},
        )
        def scoped_ok_claims_bad(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-bad-claims-ok")
        @fl_auth.required(
            scopes="impossible-scope",
            claims={"realm_access.roles": ["offline_access"]},
        )
        def scoped_bad_claims_ok(token: IDToken):
            return jsonify({"sub": token.sub})

    return register


def _create_flask_app(auth: OIDCAuth) -> Any:
    from flask import Flask

    from py_oidc_auth import FlaskOIDCAuth

    fl = FlaskOIDCAuth(**_make_auth_kwargs(auth))
    app = Flask(__name__)
    app.register_blueprint(fl.create_auth_blueprint(prefix="/api/test"))
    _flask_endpoints(fl)(app)
    return app


def _quart_endpoints(qt_auth: Any) -> Callable:
    """Register test endpoints on a Quart app."""
    from quart import jsonify

    def register(app: Any) -> None:
        @app.get("/protected")
        @qt_auth.required()
        async def protected(token: IDToken):
            return jsonify(
                {"sub": token.sub, "preferred_username": token.preferred_username}
            )

        @app.get("/protected-claims")
        @qt_auth.required(claims={"realm_access.roles": ["offline_access"]})
        async def protected_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/protected-bad-claims")
        @qt_auth.required(
            claims={"realm_access.roles": ["nonexistent-role"]}
        )
        async def protected_bad_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/optional")
        @qt_auth.optional()
        async def optional_auth(token: Optional[IDToken]):
            if token:
                return jsonify({"authenticated": True, "sub": token.sub})
            return jsonify({"authenticated": False})

        @app.get("/scoped-valid")
        @qt_auth.required(scopes="profile email")
        async def scoped_valid(token: IDToken):
            return jsonify({"sub": token.sub, "scope": token.scope})

        @app.get("/scoped-single")
        @qt_auth.required(scopes="profile")
        async def scoped_single(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-bad")
        @qt_auth.required(scopes="admin superuser")
        async def scoped_bad(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-partial")
        @qt_auth.required(scopes="profile nonexistent-scope")
        async def scoped_partial(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-and-claims")
        @qt_auth.required(
            scopes="profile",
            claims={"realm_access.roles": ["offline_access"]},
        )
        async def scoped_and_claims(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-ok-claims-bad")
        @qt_auth.required(
            scopes="profile",
            claims={"realm_access.roles": ["nonexistent-role"]},
        )
        async def scoped_ok_claims_bad(token: IDToken):
            return jsonify({"sub": token.sub})

        @app.get("/scoped-bad-claims-ok")
        @qt_auth.required(
            scopes="impossible-scope",
            claims={"realm_access.roles": ["offline_access"]},
        )
        async def scoped_bad_claims_ok(token: IDToken):
            return jsonify({"sub": token.sub})

    return register


def _create_quart_app(auth: OIDCAuth) -> Any:
    from quart import Quart

    from py_oidc_auth import QuartOIDCAuth

    qt = QuartOIDCAuth(**_make_auth_kwargs(auth))
    app = Quart(__name__)
    app.register_blueprint(qt.create_auth_blueprint(prefix="/api/test"))
    _quart_endpoints(qt)(app)
    return app


def _create_tornado_app(auth: OIDCAuth) -> Any:
    import json

    import tornado.web

    from py_oidc_auth import TornadoOIDCAuth

    tn = TornadoOIDCAuth(**_make_auth_kwargs(auth))

    # Build custom endpoint handlers
    class ProtectedHandler(tornado.web.RequestHandler):
        @tn.required()
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(
                json.dumps(
                    {
                        "sub": token.sub,
                        "preferred_username": token.preferred_username,
                    }
                )
            )

    class ProtectedClaimsHandler(tornado.web.RequestHandler):
        @tn.required(claims={"realm_access.roles": ["offline_access"]})
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class ProtectedBadClaimsHandler(tornado.web.RequestHandler):
        @tn.required(claims={"realm_access.roles": ["nonexistent-role"]})
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class OptionalHandler(tornado.web.RequestHandler):
        @tn.optional()
        async def get(self, token: Optional[IDToken]) -> None:
            self.set_header("Content-Type", "application/json")
            if token:
                self.write(
                    json.dumps({"authenticated": True, "sub": token.sub})
                )
            else:
                self.write(json.dumps({"authenticated": False}))

    class ScopedValidHandler(tornado.web.RequestHandler):
        @tn.required(scopes="profile email")
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub, "scope": token.scope}))

    class ScopedSingleHandler(tornado.web.RequestHandler):
        @tn.required(scopes="profile")
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class ScopedBadHandler(tornado.web.RequestHandler):
        @tn.required(scopes="admin superuser")
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class ScopedPartialHandler(tornado.web.RequestHandler):
        @tn.required(scopes="profile nonexistent-scope")
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class ScopedAndClaimsHandler(tornado.web.RequestHandler):
        @tn.required(
            scopes="profile",
            claims={"realm_access.roles": ["offline_access"]},
        )
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class ScopedOkClaimsBadHandler(tornado.web.RequestHandler):
        @tn.required(
            scopes="profile",
            claims={"realm_access.roles": ["nonexistent-role"]},
        )
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    class ScopedBadClaimsOkHandler(tornado.web.RequestHandler):
        @tn.required(
            scopes="impossible-scope",
            claims={"realm_access.roles": ["offline_access"]},
        )
        async def get(self, token: IDToken) -> None:
            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({"sub": token.sub}))

    app = tornado.web.Application(
        tn.get_auth_routes(prefix="/api/test")
        + [
            (r"/protected", ProtectedHandler),
            (r"/protected-claims", ProtectedClaimsHandler),
            (r"/protected-bad-claims", ProtectedBadClaimsHandler),
            (r"/optional", OptionalHandler),
            (r"/scoped-valid", ScopedValidHandler),
            (r"/scoped-single", ScopedSingleHandler),
            (r"/scoped-bad", ScopedBadHandler),
            (r"/scoped-partial", ScopedPartialHandler),
            (r"/scoped-and-claims", ScopedAndClaimsHandler),
            (r"/scoped-ok-claims-bad", ScopedOkClaimsBadHandler),
            (r"/scoped-bad-claims-ok", ScopedBadClaimsOkHandler),
        ]
    )
    return app


def _create_litestar_app(auth: OIDCAuth) -> Any:
    from litestar import Litestar, get

    from py_oidc_auth import LitestarOIDCAuth

    ls = LitestarOIDCAuth(**_make_auth_kwargs(auth))

    @get("/protected", dependencies={"token": ls.required()})
    async def protected(token: IDToken) -> dict:
        return {
            "sub": token.sub,
            "preferred_username": token.preferred_username,
        }

    @get(
        "/protected-claims",
        dependencies={
            "token": ls.required(
                claims={"realm_access.roles": ["offline_access"]}
            )
        },
    )
    async def protected_claims(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get(
        "/protected-bad-claims",
        dependencies={
            "token": ls.required(
                claims={"realm_access.roles": ["nonexistent-role"]}
            )
        },
    )
    async def protected_bad_claims(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get("/optional", dependencies={"token": ls.optional()})
    async def optional_auth(token: Optional[IDToken]) -> dict:
        if token:
            return {"authenticated": True, "sub": token.sub}
        return {"authenticated": False}

    @get(
        "/scoped-valid",
        dependencies={"token": ls.required(scopes="profile email")},
    )
    async def scoped_valid(token: IDToken) -> dict:
        return {"sub": token.sub, "scope": token.scope}

    @get(
        "/scoped-single",
        dependencies={"token": ls.required(scopes="profile")},
    )
    async def scoped_single(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get(
        "/scoped-bad",
        dependencies={"token": ls.required(scopes="admin superuser")},
    )
    async def scoped_bad(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get(
        "/scoped-partial",
        dependencies={
            "token": ls.required(scopes="profile nonexistent-scope")
        },
    )
    async def scoped_partial(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get(
        "/scoped-and-claims",
        dependencies={
            "token": ls.required(
                scopes="profile",
                claims={"realm_access.roles": ["offline_access"]},
            )
        },
    )
    async def scoped_and_claims(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get(
        "/scoped-ok-claims-bad",
        dependencies={
            "token": ls.required(
                scopes="profile",
                claims={"realm_access.roles": ["nonexistent-role"]},
            )
        },
    )
    async def scoped_ok_claims_bad(token: IDToken) -> dict:
        return {"sub": token.sub}

    @get(
        "/scoped-bad-claims-ok",
        dependencies={
            "token": ls.required(
                scopes="impossible-scope",
                claims={"realm_access.roles": ["offline_access"]},
            )
        },
    )
    async def scoped_bad_claims_ok(token: IDToken) -> dict:
        return {"sub": token.sub}

    app = Litestar(
        route_handlers=[
            ls.create_auth_router(prefix="/api/test"),
            protected,
            protected_claims,
            protected_bad_claims,
            optional_auth,
            scoped_valid,
            scoped_single,
            scoped_bad,
            scoped_partial,
            scoped_and_claims,
            scoped_ok_claims_bad,
            scoped_bad_claims_ok,
        ],
    )
    return app


def _create_django_app(auth: OIDCAuth) -> Any:
    import django
    from django.conf import settings

    from py_oidc_auth import DjangoOIDCAuth

    dj = DjangoOIDCAuth(**_make_auth_kwargs(auth))

    # -- Build views -------------------------------------------------------
    from django.http import HttpRequest, JsonResponse

    @dj.required()
    async def protected(request: HttpRequest, token: IDToken) -> JsonResponse:
        return JsonResponse(
            {"sub": token.sub, "preferred_username": token.preferred_username}
        )

    @dj.required(claims={"realm_access.roles": ["offline_access"]})
    async def protected_claims(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.required(claims={"realm_access.roles": ["nonexistent-role"]})
    async def protected_bad_claims(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.optional()
    async def optional_auth(
        request: HttpRequest, token: Optional[IDToken]
    ) -> JsonResponse:
        if token:
            return JsonResponse({"authenticated": True, "sub": token.sub})
        return JsonResponse({"authenticated": False})

    @dj.required(scopes="profile email")
    async def scoped_valid(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub, "scope": token.scope})

    @dj.required(scopes="profile")
    async def scoped_single(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.required(scopes="admin superuser")
    async def scoped_bad(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.required(scopes="profile nonexistent-scope")
    async def scoped_partial(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.required(
        scopes="profile",
        claims={"realm_access.roles": ["offline_access"]},
    )
    async def scoped_and_claims(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.required(
        scopes="profile",
        claims={"realm_access.roles": ["nonexistent-role"]},
    )
    async def scoped_ok_claims_bad(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    @dj.required(
        scopes="impossible-scope",
        claims={"realm_access.roles": ["offline_access"]},
    )
    async def scoped_bad_claims_ok(
        request: HttpRequest, token: IDToken
    ) -> JsonResponse:
        return JsonResponse({"sub": token.sub})

    # -- Create URL module dynamically -------------------------------------
    from django.urls import path

    urls_module = types.ModuleType("_test_django_urls")
    urls_module.urlpatterns = [  # type: ignore[attr-defined]
        path(
            "api/test/", lambda r: None, name="prefix"
        ),  # Placeholder — real routes below
    ]
    urls_module.urlpatterns = [
        path("api/test/", __import__("django.urls", fromlist=["include"]).include(
            dj.get_urlpatterns()
        )),
        path("protected", protected),
        path("protected-claims", protected_claims),
        path("protected-bad-claims", protected_bad_claims),
        path("optional", optional_auth),
        path("scoped-valid", scoped_valid),
        path("scoped-single", scoped_single),
        path("scoped-bad", scoped_bad),
        path("scoped-partial", scoped_partial),
        path("scoped-and-claims", scoped_and_claims),
        path("scoped-ok-claims-bad", scoped_ok_claims_bad),
        path("scoped-bad-claims-ok", scoped_bad_claims_ok),
    ]
    sys.modules["_test_django_urls"] = urls_module

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            SECRET_KEY="test-secret-key",
            ROOT_URLCONF="_test_django_urls",
            ALLOWED_HOSTS=["*"],
        )
        django.setup()
    else:
        settings.ROOT_URLCONF = "_test_django_urls"

    from django.core.asgi import get_asgi_application

    return get_asgi_application()


# =========================================================================
# Server launchers
# =========================================================================


def _start_uvicorn(app: Any, host: str, port: int) -> None:
    """Start uvicorn for ASGI apps (FastAPI, Quart, Litestar, Django)."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="debug")


def _start_flask(app: Any, host: str, port: int) -> None:
    app.run(host=host, port=port, use_reloader=False)


def _start_tornado(app: Any, host: str, port: int) -> None:
    import tornado.ioloop

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app.listen(port, address=host)
    tornado.ioloop.IOLoop.current().start()


# Map backend name → (factory, launcher, health_path)
_BACKENDS: Dict[str, tuple] = {
    "fastapi": (_create_fastapi_app, _start_uvicorn, "/docs"),
    "flask": (_create_flask_app, _start_flask, "/api/test/auth/v2/login"),
    "quart": (_create_quart_app, _start_uvicorn, "/api/test/auth/v2/login"),
    "tornado": (
        _create_tornado_app,
        _start_tornado,
        "/api/test/auth/v2/login",
    ),
    "litestar": (_create_litestar_app, _start_uvicorn, "/api/test/auth/v2/login"),
    "django": (_create_django_app, _start_uvicorn, "/api/test/auth/v2/login"),
}


def _available_backends() -> list:
    """Return backends whose framework dependency is importable."""
    checks = {
        "fastapi": "fastapi",
        "flask": "flask",
        "quart": "quart",
        "tornado": "tornado",
        "litestar": "litestar",
        "django": "django",
    }
    available = []
    for name, module in checks.items():
        try:
            __import__(module)
            available.append(name)
        except ImportError:
            pass
    return available


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def oidc_auth() -> OIDCAuth:
    """A fully configured OIDCAuth instance pointing at the real Keycloak."""
    return OIDCAuth(
        client_id=CLIENT_ID,
        discovery_url=DISCOVERY_URL,
        client_secret=CLIENT_SECRET or None,
        scopes="profile email",
        proxy="http://localhost",
        claims={"realm_access.roles": ["offline_access"]},
    )


@pytest.fixture(scope="session")
def oidc_config(oidc_auth: OIDCAuth) -> OIDCConfig:
    return oidc_auth.config


@pytest.fixture(scope="session")
def discovery(oidc_config: OIDCConfig) -> Dict[str, Any]:
    return oidc_config.oidc_overview


@pytest.fixture(scope="session")
def real_token_data() -> Dict[str, Any]:
    return _get_token_via_password_grant()


@pytest.fixture(scope="session")
def access_token(real_token_data: Dict[str, Any]) -> str:
    return real_token_data["access_token"]


@pytest.fixture(scope="session")
def refresh_token(real_token_data: Dict[str, Any]) -> str:
    return real_token_data["refresh_token"]


@pytest.fixture(scope="session")
def auth_headers(access_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture(scope="session", params=_available_backends())
def test_server(
    request: pytest.FixtureRequest, oidc_auth: OIDCAuth
) -> Iterator[str]:
    """Start a live test server in a background thread.

    Parametrized over all installed framework backends.
    """
    backend = request.param
    factory, launcher, health_path = _BACKENDS[backend]
    port = _find_free_port()
    host = "127.0.0.1"

    app = factory(oidc_auth)
    thread = threading.Thread(
        target=launcher, args=(app, host, port), daemon=True
    )
    thread.start()

    base_url = f"http://{host}:{port}"
    _wait_for_server(base_url + health_path)

    yield base_url
