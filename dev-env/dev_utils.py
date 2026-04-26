"""Service utilities."""

import argparse
import datetime
import logging
import os
import time
import urllib.request
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    import pip

    pip.main(["install", "cryptography"])
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID


logger = logging.getLogger(__name__)


def wait_for_oidc(namespace: argparse.Namespace) -> None:
    """Wait for openid connect server an exit."""
    time_passed = 0
    while time_passed < namespace.timeout:
        try:
            print(f"Trying {namespace.url}...", end="")
            conn = urllib.request.urlopen(namespace.url)
            print(f"{conn.status}")
            if conn.status == 200:
                return
        except Exception as error:
            print(error)
        time.sleep(namespace.time_increment)
        time_passed += namespace.time_increment
    raise SystemExit("Open ID connect service is not up.")


class RandomKeys:
    """Generate public and private server keys.

    Parameters:
        base_name (str): The path prefix for all key files.
        common_name (str): The common name for the certificate.
    """

    def __init__(
        self, base_name: str = "freva", common_name: str = "localhost"
    ) -> None:
        self.base_name = base_name
        self.common_name = common_name
        self._private_key_pem: Optional[bytes] = None
        self._public_key_pem: Optional[bytes] = None
        self._private_key: Optional["rsa.RSAPrivateKey"] = None

    @classmethod
    def gen_certs(cls, namespace: argparse.Namespace) -> None:
        """Generate a new pair of keys."""
        keys = cls()
        namespace.cert_dir.mkdir(exist_ok=True, parents=True)
        private_key_file = namespace.cert_dir / "client-key.pem"
        public_cert_file = namespace.cert_dir / "client-cert.pem"
        private_key_file.write_bytes(keys.private_key_pem)
        private_key_file.chmod(0o600)
        public_cert_file.write_bytes(keys.certificate_chain)

    @property
    def private_key(self) -> "rsa.RSAPrivateKey":
        if self._private_key is not None:
            return self._private_key
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return self._private_key

    @property
    def private_key_pem(self) -> bytes:
        """Create a new private key pem if it doesn't exist."""
        if self._private_key_pem is None:
            self._private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        return self._private_key_pem

    @property
    def public_key_pem(self) -> bytes:
        """
        Generate a public key pair using RSA algorithm.

        Returns:
            bytes: The public key (PEM format).
        """
        if self._public_key_pem is None:
            public_key = self.private_key.public_key()
            self._public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return self._public_key_pem

    def create_self_signed_cert(self) -> "x509.Certificate":
        """
        Create a self-signed certificate using the public key.

        Returns
        -------
            x509.Certificate: The self-signed certificate.
        """
        certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)])
            )
            .issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)])
            )
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )

        return certificate

    @property
    def certificate_chain(self) -> bytes:
        """The certificate chain."""
        certificate = self.create_self_signed_cert()
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        return self.public_key_pem + certificate_pem


@asynccontextmanager
async def lifespan(app: "FastAPI") -> AsyncIterator[None]:
    """Start and end things before and after shutdown.

    Things before yield are executed on startup. Things after on teardown.
    """
    logger.info(
        "Visit http://localhost:%s/api/test/help",
        os.getenv("SERVER_PORT"),
    )
    yield


# =========================================================================
# App factories
# =========================================================================


def _create_fastapi_app() -> "FastAPI":
    """App factory for FastAPI."""
    from fastapi import FastAPI

    from py_oidc_auth import (
        FastApiOIDCAuth,
        IDToken,
        __version__,
        string_to_dict,
    )

    logger.setLevel(logging.DEBUG)

    app = FastAPI(
        debug=True,
        title="Test Auth server",
        version=__version__,
        openapi_url="/api/test/help/openapi.json",
        docs_url=None,
        redoc_url="/api/test/help",
        description="Test auth server",
        lifespan=lifespan,
    )
    auth = FastApiOIDCAuth(
        discovery_url=os.getenv("OIDC_DISCOVERY_URL"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET") or None,
        scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        broker_mode=bool(int(os.getenv("OIDC_BROKER_MODE"))),
    )
    app.include_router(auth.create_auth_router(prefix="/api/test"))
    claims = string_to_dict(os.getenv("OIDC_ADMIN_CLAIM", ""))

    @app.get("/protected", tags=["Production"])
    async def protected(id_token: IDToken = auth.required()):
        print(id_token)

    @app.get("/optional", tags=["Production"])
    async def optional(id_token: IDToken = auth.optional()):
        print(id_token)

    @app.get("/admin", tags=["Production"])
    async def admin(id_token: IDToken = auth.required(claims=claims)):
        print(id_token)

    return app


def _create_flask_app() -> Any:
    """App factory for Flask."""
    from flask import Flask, Response, jsonify

    from py_oidc_auth import (
        FlaskOIDCAuth,
        IDToken,
    )

    fl_auth = FlaskOIDCAuth(
        discovery_url=os.getenv("OIDC_DISCOVERY_URL"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET") or None,
        scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        broker_mode=bool(int(os.getenv("OIDC_BROKER_MODE", "0"))),
    )

    app = Flask("test")

    app.register_blueprint(fl_auth.create_auth_blueprint(prefix="/api/test"))

    @app.get("/protected")
    @fl_auth.required()
    def protected(token: IDToken):
        return jsonify(
            {"sub": token.sub, "preferred_username": token.preferred_username}
        )

    @app.get("/openapi.json")
    def openapi():
        paths = {}
        for rule in app.url_map.iter_rules():
            if rule.endpoint == "static":
                continue
            path = rule.rule
            paths.setdefault(path, {})
            for method in sorted(
                m
                for m in rule.methods
                if m in {"GET", "POST", "PUT", "PATCH", "DELETE"}
            ):
                paths[path][method.lower()] = {
                    "summary": rule.endpoint,
                    "responses": {"200": {"description": "OK"}},
                }

        spec = {
            "openapi": "3.0.3",
            "info": {"title": "My API", "version": "0.1.0"},
            "paths": paths,
        }
        return jsonify(spec)

    @app.get("/api/test/help")
    def redoc():
        html = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>API Docs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style> body { margin: 0; padding: 0; } </style>
  </head>
  <body>
    <redoc spec-url="/openapi.json"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
  </body>
</html>
"""
        return Response(html, mimetype="text/html")

    return app


def _create_quart_app() -> Any:
    """App factory for Quart."""
    from quart import Quart, jsonify

    from py_oidc_auth import IDToken, QuartOIDCAuth

    qt_auth = QuartOIDCAuth(
        discovery_url=os.getenv("OIDC_DISCOVERY_URL"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET") or None,
        scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        broker_mode=bool(int(os.getenv("OIDC_BROKER_MODE", "0"))),
    )

    app = Quart("test")
    app.register_blueprint(qt_auth.create_auth_blueprint(prefix="/api/test"))

    @app.get("/protected")
    @qt_auth.required()
    async def protected(token: IDToken):
        return jsonify(
            {"sub": token.sub, "preferred_username": token.preferred_username}
        )

    return app


def _create_tornado_app() -> Any:
    """App factory for Tornado."""
    import json

    import tornado.web

    from py_oidc_auth import IDToken, TornadoOIDCAuth

    tn_auth = TornadoOIDCAuth(
        discovery_url=os.getenv("OIDC_DISCOVERY_URL"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET") or None,
        scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        broker_mode=bool(int(os.getenv("OIDC_BROKER_MODE", "0"))),
    )

    class ProtectedHandler(tornado.web.RequestHandler):
        @tn_auth.required()
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

    app = tornado.web.Application(
        tn_auth.get_auth_routes(prefix="/api/test")
        + [(r"/protected", ProtectedHandler)]
    )
    return app


def _create_litestar_app() -> Any:
    """App factory for Litestar."""
    from litestar import Litestar, get

    from py_oidc_auth import IDToken, LitestarOIDCAuth

    ls_auth = LitestarOIDCAuth(
        discovery_url=os.getenv("OIDC_DISCOVERY_URL"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET") or None,
        scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        broker_mode=bool(int(os.getenv("OIDC_BROKER_MODE", "0"))),
    )

    @get("/protected", dependencies={"token": ls_auth.required()})
    async def protected(token: IDToken) -> dict:
        return {
            "sub": token.sub,
            "preferred_username": token.preferred_username,
        }

    app = Litestar(
        route_handlers=[
            ls_auth.create_auth_router(prefix="/api/test"),
            protected,
        ]
    )
    return app


def _create_django_app() -> Any:
    """App factory for Django (ASGI)."""
    import sys
    import types

    import django
    from django.conf import settings

    from py_oidc_auth import DjangoOIDCAuth, IDToken

    dj_auth = DjangoOIDCAuth(
        discovery_url=os.getenv("OIDC_DISCOVERY_URL"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET") or None,
        scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        broker_mode=bool(int(os.getenv("OIDC_BROKER_MODE", "0"))),
    )

    from django.http import HttpRequest, JsonResponse

    @dj_auth.required()
    async def protected(request: HttpRequest, token: IDToken) -> JsonResponse:
        return JsonResponse(
            {"sub": token.sub, "preferred_username": token.preferred_username}
        )

    from django.urls import include, path

    urls_module = types.ModuleType("_dev_django_urls")
    urls_module.urlpatterns = [  # type: ignore[attr-defined]
        path(
            "api/test/",
            include(dj_auth.get_urlpatterns()),
        ),
        path("protected", protected),
    ]
    sys.modules["_dev_django_urls"] = urls_module

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            SECRET_KEY="dev-secret-key",
            ROOT_URLCONF="_dev_django_urls",
            ALLOWED_HOSTS=["*"],
        )
        django.setup()

    from django.core.asgi import get_asgi_application

    return get_asgi_application()


# =========================================================================
# Server launchers
# =========================================================================


@contextmanager
def set_env(namespace: argparse.Namespace) -> None:
    try:
        env = os.environ.copy()
        os.environ["OIDC_DISCOVERY_URL"] = namespace.discovery_url
        os.environ["OIDC_CLIENT_ID"] = namespace.client_id
        os.environ["SERVER_PORT"] = str(namespace.port)
        if namespace.client_secret:
            os.environ["OIDC_CLIENT_SECRET"] = namespace.client_secret
        os.environ["OIDC_ADMIN_CLAIM"] = namespace.admin_claim
        os.environ["OIDC_SCOPES"] = " ".join(
            namespace.scopes or ["openid", "profileemail"]
        )
        os.environ["OIDC_BROKER_MODE"] = str(int(namespace.no_broker_mode is False))
        yield
    finally:
        os.environ = env


def run_fast_server(namespace: argparse.Namespace) -> None:
    """Run a FastAPI test server."""
    import uvicorn

    with set_env(namespace):
        uvicorn.run(
            "dev_utils:_create_fastapi_app",
            factory=True,
            host="0.0.0.0",
            port=namespace.port,
            reload=True,
            log_level="debug",
        )


def run_flask_server(namespace: argparse.Namespace) -> None:
    """Run a Flask test server."""
    with set_env(namespace):
        app = _create_flask_app()
        app.run(host="0.0.0.0", port=namespace.port, use_reloader=True)


def run_quart_server(namespace: argparse.Namespace) -> None:
    """Run a Quart test server."""
    with set_env(namespace):
        app = _create_quart_app()
        app.run(host="0.0.0.0", port=namespace.port, use_reloader=True)


def run_tornado_server(namespace: argparse.Namespace) -> None:
    """Run a Tornado test server."""

    import tornado.ioloop

    with set_env(namespace):
        app = _create_tornado_app()
        app.listen(namespace.port, address="0.0.0.0")
        print(f"Tornado server listening on http://0.0.0.0:{namespace.port}")
        tornado.ioloop.IOLoop.current().start()


def run_litestar_server(namespace: argparse.Namespace) -> None:
    """Run a Litestar test server."""
    import uvicorn

    with set_env(namespace):
        app = _create_litestar_app()
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=namespace.port,
            log_level="debug",
        )


def run_django_server(namespace: argparse.Namespace) -> None:
    """Run a Django test server (ASGI via uvicorn)."""
    import uvicorn

    with set_env(namespace):
        app = _create_django_app()
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=namespace.port,
            log_level="debug",
        )


def add_server_parser(
    name: str,
    subparser: argparse._SubParsersAction,
    runner: Any,
) -> argparse.ArgumentParser:
    """Add the server arguments."""
    parser = subparser.add_parser(
        f"{name}-server",
        help=f"Run a simple {name} test server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.set_defaults(apply=runner)
    parser.add_argument("--port", type=int, default=7777, help="Service port.")
    parser.add_argument(
        "--admin-claim", type=str, default="foo", help="Define admin claim."
    )
    parser.add_argument(
        "--discovery-url",
        type=str,
        default="http://localhost:8080/realms/freva/.well-known/openid-configuration",
        help="OIDC discovery endpoint",
    )
    parser.add_argument("--client-id", type=str, default="freva", help="OIDC client id")
    parser.add_argument(
        "--client-secret", type=str, default=None, help="OIDC client secret"
    )
    parser.add_argument(
        "--scopes",
        type=str,
        default="openid profile email",
        help="OIDC scopes",
        nargs="*",
    )
    parser.add_argument(
        "--no-broker-mode",
        action="store_true",
        help="Do not enable broker mode.",
    )
    return parser


def cli() -> None:
    """Command line interface."""
    app = argparse.ArgumentParser(
        description="Various utilities for development purpose.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    app.set_defaults(cli=RandomKeys.gen_certs)
    subparser = app.add_subparsers(
        required=True,
    )

    # -- Server subcommands (one per framework) ----------------------------
    _servers = {
        "fastapi": run_fast_server,
        "flask": run_flask_server,
        "quart": run_quart_server,
        "tornado": run_tornado_server,
        "litestar": run_litestar_server,
        "django": run_django_server,
    }
    for name, runner in _servers.items():
        add_server_parser(name, subparser, runner)

    # -- Certificate generation -------------------------------------------
    key_parser = subparser.add_parser(
        name="gen-certs",
        help="Generate a random pair of public and private certificates.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    key_parser.set_defaults(apply=RandomKeys.gen_certs)
    key_parser.add_argument(
        "--cert-dir",
        help="The ouptut directory where the certs should be stored.",
        type=Path,
        default=Path(__file__).parent / "certs",
    )

    # -- OIDC wait --------------------------------------------------------
    oidc_parser = subparser.add_parser(
        name="oidc",
        help="Wait for the oidc service to start up.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    oidc_parser.add_argument("url", help="Open ID connect discovery url.")
    oidc_parser.add_argument(
        "--timeout",
        type=int,
        default=500,
        help=(
            "The time out in s after which we should give up waiting for the service."
        ),
    )
    oidc_parser.add_argument(
        "--time-increment",
        type=int,
        default=10,
        help=(
            "Wait for <increment> seconds before attempting to contact the "
            "server again."
        ),
    )
    oidc_parser.set_defaults(apply=wait_for_oidc)
    args = app.parse_args()
    args.apply(args)


if __name__ == "__main__":
    cli()
