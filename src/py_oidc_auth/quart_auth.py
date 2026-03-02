"""Quart integration for py oidc auth.

Quart is an async framework with a Flask compatible API.
Because Quart supports ``async def`` route handlers, this adapter calls the
async base methods directly.

Install

.. code-block:: text

    pip install py-oidc-auth[quart]

Usage

.. code-block:: python

    from quart import Quart
    from py_oidc_auth.quart_auth import QuartOIDCAuth

    auth = QuartOIDCAuth(
        client_id="my client",
        client_secret="secret",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
    )

    app = Quart(__name__)
    app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

    @app.get("/protected")
    @auth.required()
    async def protected(token):
        return {"sub": token.sub}

"""

from __future__ import annotations

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
    from quart import Blueprint, Response, jsonify, redirect, request
except ImportError:  # pragma: no cover
    raise ImportError(
        "Quart integration requires the 'quart' extra. "
        "Install it with: pip install py-oidc-auth[quart]"
    ) from None

if TYPE_CHECKING:
    from werkzeug.wrapper.response import Response as WerkzeugRes

from .auth_base import OIDCAuth
from .exceptions import InvalidRequest
from .schema import IDToken, PromptField

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _error_response(status_code: int, detail: str) -> Response:
    response = jsonify({"detail": detail})
    response.status_code = status_code
    return response


class QuartOIDCAuth(OIDCAuth):
    """Reusable OpenID Connect helper for Quart."""

    def _extract_bearer_token(self) -> Optional[str]:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def required(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Enforce authentication on a Quart route.

        The decorated handler receives :class:`~py_oidc_auth.schema.IDToken` as
        its first positional argument.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: Decorator for Quart routes.

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                credentials = self._extract_bearer_token()
                try:
                    token = await self._get_token(
                        credentials,
                        required_scopes=scope_set or None,
                        effective_claims=effective_claims,
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return await fn(token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def optional(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Allow anonymous access decorator.

        The decorated handler receives :class:`~py_oidc_auth.schema.IDToken` or
        ``None`` as its first positional argument.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: Decorator for Quart routes.

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                credentials = self._extract_bearer_token()
                token: Optional[IDToken] = None
                if credentials:
                    try:
                        token = await self._get_token(
                            credentials,
                            required_scopes=scope_set or None,
                            effective_claims=effective_claims,
                        )
                    except InvalidRequest:
                        pass
                return await fn(token, *args, **kwargs)

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
        """Build a Quart :class:`quart.Blueprint` with standard auth routes.

        :param prefix: URL prefix for all routes.
        :param login: Path for login.
        :param callback: Path for callback.
        :param token: Path for token exchange and refresh.
        :param device_flow: Path for starting the device flow.
        :param logout: Path for logout.
        :param userinfo: Path for userinfo.
        :returns: Blueprint to register on your app.

        Request example

        .. code-block:: text

            GET /auth/v2/userinfo HTTP/1.1
            Host: app.example.org
            Authorization: Bearer <access token>

        """
        bp = Blueprint("oidc_auth", __name__, url_prefix=prefix)

        if login:

            @bp.route(login, methods=["GET"])
            async def _login() -> Union[Response, "WerkzeugRes"]:
                redirect_uri = request.args.get("redirect_uri")
                prompt = request.args.get("prompt", "none")
                offline_access = (
                    request.args.get("offline_access", "false").lower() == "true"
                )
                scope = request.args.get("scope")
                try:
                    auth_url = await self.login(
                        redirect_uri=redirect_uri,
                        prompt=cast(PromptField, prompt),
                        offline_access=offline_access,
                        scope=scope,
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return redirect(auth_url)

        if callback:

            @bp.route(callback, methods=["GET"])
            async def _callback() -> Response:
                code = request.args.get("code")
                state = request.args.get("state")
                try:
                    result = await self.callback(code=code, state=state)
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result)

        if device_flow:

            @bp.route(device_flow, methods=["POST"])
            async def _device_flow() -> Response:
                try:
                    result = await self.device_flow()
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        if token:

            @bp.route(token, methods=["POST"])
            async def _fetch_or_refresh_token() -> Response:
                form = await request.form
                code = form.get("code")
                redirect_uri = form.get("redirect_uri")
                refresh_token = form.get("refresh-token")
                device_code = form.get("device-code")
                code_verifier = form.get("code_verifier")
                try:
                    result = await self.token(
                        f"{prefix}/{token}",
                        code=code,
                        redirect_uri=redirect_uri,
                        refresh_token=refresh_token,
                        device_code=device_code,
                        code_verifier=code_verifier,
                    )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        if logout:

            @bp.route(logout, methods=["GET"])
            async def _logout() -> Union[Response, "WerkzeugRes"]:
                post_logout_redirect_uri = request.args.get(
                    "post_logout_redirect_uri"
                )
                target = await self.logout(post_logout_redirect_uri)
                return redirect(target)

        if userinfo:

            @bp.route(userinfo, methods=["GET"])
            @self.required()
            async def _userinfo(token: IDToken) -> Response:
                try:
                    result = await self.userinfo(token, dict(request.headers))
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        return bp
