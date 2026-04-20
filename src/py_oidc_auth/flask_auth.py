"""Flask integration for py oidc auth.

Flask view functions are synchronous.
The base implementation is async, so this adapter uses ``asyncio.run`` to call
the async methods.  The broker ``verify()`` call is synchronous and is called
directly.

Flask view functions are synchronous.  The base implementation is async, so
this adapter uses ``asyncio.run`` to call the async methods.  The broker
``verify()`` call is synchronous and is called directly.

Install::

    pip install py-oidc-auth[flask]
    conda install -c conda-forge py-oidc-auth-flask


Usage

.. code-block:: python

    from flask import Flask
    from py_oidc_auth.flask_auth import FlaskOIDCAuth

    auth = FlaskOIDCAuth(
        client_id="my client",
        client_secret="secret",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
        scopes="myscope profile email",
        broker_mode=True,
        broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
    )

    app = Flask(__name__)
    app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

    @app.get("/protected")
    @auth.required()
    def protected(token):
        return {"sub": token.sub}

"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Optional,
    TypeVar,
    Union,
    cast,
)

import jwt as pyjwt

try:
    from flask import Blueprint, Response, jsonify, redirect, request
except ImportError:  # pragma: no cover
    raise ImportError(
        "Flask integration requires the 'flask' extra. "
        "Install it with: pip install py-oidc-auth[flask]"
    ) from None

from .auth_base import OIDCAuth
from .exceptions import InvalidRequest
from .schema import IDToken, PromptField
from .utils import token_field_matches

if TYPE_CHECKING:
    from werkzeug.wrapper.response import Response as WerkzeugRes

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _error_response(status_code: int, detail: str) -> Response:
    """Create a small JSON error response."""
    response = jsonify({"detail": detail})
    response.status_code = status_code
    return response


class FlaskOIDCAuth(OIDCAuth):
    """Reusable OpenID Connect helper for Flask.

    The auth endpoints are suitable for browser based login and for programmatic
    token refresh.

    This adapter provides:

    * :meth:`required` and :meth:`optional` decorators for view functions
    * :meth:`create_auth_blueprint` to expose a standard set of auth endpoints
            When ``broker_mode=True`` the decorators verify broker JWTs and the
            blueprint token endpoints issues broker JWTs instead of passing IDP
            tokens through.
    """

    def _extract_bearer_token(self) -> Optional[str]:
        """Return the bearer token from the current Flask request."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def required(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Enforce authentication.

        The decorated view receives the validated :class:`~py_oidc_auth.schema.IDToken`
        as its first positional argument.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names the token must contain.
        :returns: Decorator for Flask views.

        Example
        -------
        .. code-block:: python

            @app.get("/admin")
            @auth.required(claims={"groups": ["admins"]}, scopes="admin")
            def admin(token):
                return {"sub": token.sub}

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bearer = self._extract_bearer_token()
                if self.broker_mode:
                    if not bearer:
                        return _error_response(401, "Missing Bearer token.")
                    try:
                        broker = asyncio.run(self._ensure_broker_ready())
                        token = broker.verify(bearer)
                    except pyjwt.ExpiredSignatureError:
                        return _error_response(401, "Token has expired.")
                    except pyjwt.PyJWTError as exc:
                        return _error_response(401, f"Invalid token: {exc}")
                    if effective_claims and not token_field_matches(
                        bearer, claims=effective_claims
                    ):
                        return _error_response(403, "Insufficient claims.")
                else:
                    try:
                        token = asyncio.run(
                            self._get_token(
                                bearer,
                                required_scopes=scope_set or None,
                                effective_claims=effective_claims,
                            )
                        )
                    except InvalidRequest as exc:
                        return _error_response(exc.status_code, exc.detail)
                return fn(token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def optional(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Allow anonymous access.

        The decorated view receives :class:`~py_oidc_auth.schema.IDToken` or
        ``None`` as its first positional argument.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: Decorator for Flask views.

        Example
        -------
        .. code-block:: python

            @app.get("/feed")
            @auth.optional()
            def feed(token):
                if token:
                    return {"message": f"Welcome {token.preferred_username}"}
                return {"message": "Welcome guest"}

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bearer = self._extract_bearer_token()
                token: Optional[IDToken] = None
                if bearer:
                    if self.broker_mode:
                        try:
                            broker = asyncio.run(self._ensure_broker_ready())
                            token = broker.verify(bearer)
                            if effective_claims and not token_field_matches(
                                bearer, claims=effective_claims
                            ):
                                token = None
                        except pyjwt.PyJWTError:
                            pass
                    else:
                        try:
                            token = asyncio.run(
                                self._get_token(
                                    bearer,
                                    required_scopes=scope_set or None,
                                    effective_claims=effective_claims,
                                )
                            )
                        except InvalidRequest:
                            pass
                return fn(token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def create_auth_blueprint(
        self,
        prefix: str = "",
        login: Optional[str] = "/auth/v2/login",
        callback: Optional[str] = "/auth/v2/callback",
        token: Optional[str] = "/auth/v2/token",
        device_flow: Optional[str] = "/auth/v2/device",
        logout: Optional[str] = "/auth/v2/logout",
        userinfo: Optional[str] = "/auth/v2/userinfo",
        jwks: Optional[str] = "/auth/v2/.well-known/jwks.json",
    ) -> Blueprint:
        """Build a Flask :class:`flask.Blueprint` with standard auth routes.

        Each route can be disabled by passing ``None`` for its path.

        :param prefix: URL prefix for all routes.
        :param login: Path for login.
        :param callback: Path for callback.
        :param token: Path for token exchange and refresh.
        :param device_flow: Path for starting the device flow.
        :param logout: Path for logout.
        :param userinfo: Path for userinfo.
        :param jwks: Path for the JWKS endpoint (broker mode only).
        :returns: A blueprint ready to be registered on your app.
        :raises ValueError: When ``broker_mode=True`` and ``token`` is falsy.

        Request examples

        .. code-block:: text

            GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
            Host: app.example.org

        .. code-block:: text

            POST /auth/v2/token HTTP/1.1
            Host: app.example.org
            Content-Type: application/x-www-form-urlencoded

            refresh_token=ref

        """
        bp = Blueprint("oidc_auth", __name__, url_prefix=prefix)

        if login:

            @bp.route(login, methods=["GET"])
            def _login() -> Union[Response, "WerkzeugRes"]:
                offline = request.args.get("offline_access", "false").lower()
                redirect_uri = request.args.get("redirect_uri")
                prompt = cast(PromptField, request.args.get("prompt", "none"))
                scope = request.args.get("scope")
                try:
                    auth_url = asyncio.run(
                        self.login(
                            redirect_uri=redirect_uri,
                            prompt=prompt,
                            offline_access=offline == "true",
                            scope=scope,
                        )
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return redirect(auth_url)

        if callback:

            @bp.route(callback, methods=["GET"])
            def _callback() -> Response:
                code = request.args.get("code")
                state = request.args.get("state")
                try:
                    result = asyncio.run(self.callback(code=code, state=state))
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result)

        if device_flow:

            @bp.route(device_flow, methods=["POST"])
            def _device_flow() -> Response:
                try:
                    result = asyncio.run(self.device_flow())
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        if token:
            _token_endpoint = f"{prefix}{token}"

            @bp.route(token, methods=["POST"])
            def _fetch_or_refresh_token() -> Union[Response, "WerkzeugRes"]:
                code = request.form.get("code")
                redirect_uri = request.form.get("redirect_uri")
                refresh_token = request.form.get("refresh-token")
                device_code = request.form.get("device-code")
                code_verifier = request.form.get("code_verifier")
                grant_type = request.form.get("grant_type")
                subject_token = request.form.get("subject_token")
                try:
                    if self.broker_mode:
                        result = asyncio.run(
                            self.broker_token(
                                token_endpoint=_token_endpoint,
                                code=code,
                                redirect_uri=redirect_uri,
                                refresh_token=refresh_token,
                                device_code=device_code,
                                code_verifier=code_verifier,
                                grant_type=grant_type,
                                subject_token=subject_token,
                            )
                        )
                    else:
                        result = asyncio.run(
                            self.token(
                                _token_endpoint,
                                code=code,
                                redirect_uri=redirect_uri,
                                refresh_token=refresh_token,
                                device_code=device_code,
                                code_verifier=code_verifier,
                            )
                        )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        if jwks and self.broker_mode:

            @bp.route(jwks, methods=["GET"])
            def _jwks() -> Response:
                return jsonify(asyncio.run(self.broker_jwks()))

        if logout:

            @bp.route(logout, methods=["GET"])
            def _logout() -> Union[Response, "WerkzeugRes"]:
                post_logout_redirect_uri = request.args.get("post_logout_redirect_uri")
                redirect_target = asyncio.run(self.logout(post_logout_redirect_uri))
                return redirect(redirect_target)

        if userinfo:

            @bp.route(userinfo, methods=["GET"])
            @self.required()
            def _userinfo(token_obj: IDToken) -> Response:
                try:
                    result = asyncio.run(
                        self.userinfo(token_obj, dict(request.headers))
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        return bp
