"""Flask integration for py oidc auth.

Flask view functions are synchronous.
The base implementation is async, so this adapter uses ``asyncio.run`` to call
the async methods.

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

    This adapter provides:

    * :meth:`required` and :meth:`optional` decorators for view functions
    * :meth:`create_auth_blueprint` to expose a standard set of auth endpoints

    The auth endpoints are suitable for browser based login and for programmatic
    token refresh.

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
                credentials = self._extract_bearer_token()
                try:
                    token = asyncio.run(
                        self._get_token(
                            credentials,
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
                credentials = self._extract_bearer_token()
                token: Optional[IDToken] = None
                if credentials:
                    try:
                        token = asyncio.run(
                            self._get_token(
                                credentials,
                                required_scopes=scope_set or None,
                                effective_claims=effective_claims,
                            )
                        )
                    except InvalidRequest:
                        logger.info("Optional auth validation failed")
                return fn(token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def create_auth_blueprint(
        self,
        prefix: str = "",
        login: str = "/auth/v2/login",
        callback: str = "/auth/v2/callback",
        token: str = "/auth/v2/token",
        device_flow: Optional[str] = "/auth/v2/device",
        logout: Optional[str] = "/auth/v2/logout",
        userinfo: Optional[str] = "/auth/v2/userinfo",
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
        :returns: A blueprint ready to be registered on your app.

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

            @bp.route(token, methods=["POST"])
            def _fetch_or_refresh_token() -> Union[Response, "WerkzeugRes"]:
                code = request.form.get("code")
                redirect_uri = request.form.get("redirect_uri")
                refresh_token = request.form.get("refresh-token")
                device_code = request.form.get("device-code")
                code_verifier = request.form.get("code_verifier")
                try:
                    result = asyncio.run(
                        self.token(
                            f"{prefix}/{token}",
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

        if logout:

            @bp.route(logout, methods=["GET"])
            def _logout() -> Union[Response, "WerkzeugRes"]:
                post_logout_redirect_uri = request.args.get(
                    "post_logout_redirect_uri"
                )
                redirect_target = asyncio.run(
                    self.logout(post_logout_redirect_uri)
                )
                return redirect(redirect_target)

        if userinfo:

            @bp.route(userinfo, methods=["GET"])
            @self.required()
            def _userinfo(token: IDToken) -> Response:
                try:
                    result = asyncio.run(
                        self.userinfo(token, dict(request.headers))
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        return bp
