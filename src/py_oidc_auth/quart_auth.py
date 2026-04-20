"""Quart integration for py oidc auth.

Quart is an async framework with a Flask compatible API.
Because Quart supports ``async def`` route handlers, this adapter calls the
async base methods directly.

Install::

    pip install py-oidc-auth[quart]
    conda install -c conda-forge py-oidc-auth-quart

Usage

.. code-block:: python

    from quart import Quart
    from py_oidc_auth.quart_auth import QuartOIDCAuth

    auth = QuartOIDCAuth(
        client_id="my client",
        client_secret="secret",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
        scopes="myscope profile email",
        broker_mode=True,
        broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
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

import jwt as pyjwt

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
from .utils import token_field_matches

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _error_response(status_code: int, detail: str) -> Response:
    response = jsonify({"detail": detail})
    response.status_code = status_code
    return response


class QuartOIDCAuth(OIDCAuth):
    """Reusable OpenID Connect helper for Quart.

    Provides :meth:`required` :meth:`optional` decorators and
    :meth:`create_auth_blueprint` for standard auth endpoints.  When
    ``broker_mode=True`` the decorators verify broker JWTs and the blueprint
    token endpoint issues broker JWTs instead of passing IDP tokens through.
    """

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
                bearer = self._extract_bearer_token()
                if self.broker_mode:
                    if not bearer:
                        return _error_response(401, "Missing Bearer token.")
                    try:
                        broker = await self._ensure_broker_ready()
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
                        token = await self._get_token(
                            bearer,
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
                bearer = self._extract_bearer_token()
                token: Optional[IDToken] = None
                if bearer:
                    if self.broker_mode:
                        try:
                            broker = await self._ensure_broker_ready()
                            token = broker.verify(bearer)
                            if effective_claims and not token_field_matches(
                                bearer, claims=effective_claims
                            ):
                                token = None
                        except pyjwt.PyJWTError:
                            pass
                    else:
                        try:
                            token = await self._get_token(
                                bearer,
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
        login: Optional[str] = "/auth/v2/login",
        callback: Optional[str] = "/auth/v2/callback",
        token: Optional[str] = "/auth/v2/token",
        device_flow: Optional[str] = "/auth/v2/device",
        logout: Optional[str] = "/auth/v2/logout",
        userinfo: Optional[str] = "/auth/v2/userinfo",
        jwks: Optional[str] = "/auth/v2/.well-known/jwks.json",
    ) -> Blueprint:
        """Build a Quart :class:`quart.Blueprint` with standard auth routes.

        :param prefix: URL prefix for all routes.
        :param login: Path for login.
        :param callback: Path for callback.
        :param token: Path for token exchange and refresh.
        :param device_flow: Path for starting the device flow.
        :param logout: Path for logout.
        :param userinfo: Path for userinfo.
        :param jwks: Path for the JWKS endpoint (broker mode only).
        :returns: Blueprint to register on your app.
        :raises ValueError: When ``broker_mode=True`` and ``token`` is falsy.

        Request example

        .. code-block:: text

            GET /auth/v2/userinfo HTTP/1.1
            Host: app.example.org
            Authorization: Bearer <access token>

        """
        self._validate_broker_config(has_token_endpoint=bool(token))

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
            _token_endpoint = f"{prefix}{token}"

            @bp.route(token, methods=["POST"])
            async def _fetch_or_refresh_token() -> Response:
                form = await request.form
                code = form.get("code")
                redirect_uri = form.get("redirect_uri")
                refresh_token = form.get("refresh-token")
                device_code = form.get("device-code")
                code_verifier = form.get("code_verifier")
                grant_type = form.get("grant_type")
                subject_token = form.get("subject_token")
                try:
                    if self.broker_mode:
                        result = await self.broker_token(
                            token_endpoint=_token_endpoint,
                            code=code,
                            redirect_uri=redirect_uri,
                            refresh_token=refresh_token,
                            device_code=device_code,
                            code_verifier=code_verifier,
                            grant_type=grant_type,
                            subject_token=subject_token,
                        )
                    else:
                        result = await self.token(
                            _token_endpoint,
                            code=code,
                            redirect_uri=redirect_uri,
                            refresh_token=refresh_token,
                            device_code=device_code,
                            code_verifier=code_verifier,
                        )
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        if jwks and self.broker_mode:

            @bp.route(jwks, methods=["GET"])
            async def _jwks() -> Response:
                return jsonify(await self.broker_jwks())

        if logout:

            @bp.route(logout, methods=["GET"])
            async def _logout() -> Union[Response, "WerkzeugRes"]:
                post_logout_redirect_uri = request.args.get("post_logout_redirect_uri")
                target = await self.logout(post_logout_redirect_uri)
                return redirect(target)

        if userinfo:

            @bp.route(userinfo, methods=["GET"])
            @self.required()
            async def _userinfo(token_obj: IDToken) -> Response:
                try:
                    result = await self.userinfo(token_obj, dict(request.headers))
                except InvalidRequest as exc:
                    return _error_response(exc.status_code, exc.detail)
                return jsonify(result.model_dump())

        return bp
