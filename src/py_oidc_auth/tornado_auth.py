"""Tornado integration for py oidc auth.

Tornado supports asyncio based request handlers.
This adapter calls the async base implementation directly.

Install::

    pip install py-oidc-auth[tornado]
    conda install -c conda-forge py-oidc-auth-tornado

Usage

.. code-block:: python

    import tornado.web
    import tornado.ioloop
    from py_oidc_auth.tornado_auth import TornadoOIDCAuth

    auth = TornadoOIDCAuth(
        client_id="my client",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
        scopes="myscope profile email",
        broker_mode=True,
        broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
    )

    class ProtectedHandler(tornado.web.RequestHandler):
        @auth.required()
        async def get(self, token):
            self.write({"sub": token.sub})

    app = tornado.web.Application(
        auth.get_auth_routes(prefix="/api") + [(r"/protected", ProtectedHandler)]
    )
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()

"""

from __future__ import annotations

import functools
import json
import logging
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    cast,
)

import jwt as pyjwt

try:
    import tornado.web
except ImportError:  # pragma: no cover
    raise ImportError(
        "Tornado integration requires the 'tornado' extra. "
        "Install it with: pip install py-oidc-auth[tornado]"
    ) from None

from .auth_base import OIDCAuth
from .exceptions import InvalidRequest
from .schema import IDToken, PromptField
from .utils import token_field_matches

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def _write_error(
    handler: tornado.web.RequestHandler,
    status_code: int,
    detail: str,
) -> None:
    """Write a JSON error to a Tornado request handler."""
    handler.set_status(status_code)
    handler.set_header("Content-Type", "application/json")
    handler.write(json.dumps({"detail": detail}))
    handler.finish()


class TornadoOIDCAuth(OIDCAuth):
    """Reusable OpenID Connect helper for Tornado.

    Use :meth:`required` and :meth:`optional` as decorators for handler methods.
    Use :meth:`get_auth_routes` to add standard auth endpoints. When
    ``broker_mode=True`` the decorators verify broker JWTs and the token
    handler issues broker JWTs instead of passing IDP tokens through.
    """

    @staticmethod
    def _extract_bearer(handler: tornado.web.RequestHandler) -> Optional[str]:
        auth_header = handler.request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def required(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Enforce authentication.

        The decorated method receives :class:`~py_oidc_auth.schema.IDToken` as
        an extra argument.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: Decorator for Tornado handler methods.

        Example
        -------
        .. code-block:: python

            class MyHandler(tornado.web.RequestHandler):
                @auth.required(scopes="admin")
                async def get(self, token):
                    self.write({"sub": token.sub})

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(method: F) -> F:
            @functools.wraps(method)
            async def wrapper(
                handler: tornado.web.RequestHandler,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                bearer = self._extract_bearer(handler)
                if self.broker_mode:
                    if not bearer:
                        _write_error(handler, 401, "Missing Bearer token.")
                        return
                    try:
                        broker = await self._ensure_broker_ready()
                        token = broker.verify(bearer)
                    except pyjwt.ExpiredSignatureError:
                        _write_error(handler, 401, "Token has expired.")
                        return
                    except pyjwt.PyJWTError as exc:
                        _write_error(handler, 401, f"Invalid token: {exc}")
                        return
                    if effective_claims and not token_field_matches(
                        bearer, claims=effective_claims
                    ):
                        _write_error(handler, 403, "Insufficient claims.")
                        return
                else:
                    try:
                        token = await self._get_token(
                            bearer,
                            required_scopes=scope_set or None,
                            effective_claims=effective_claims,
                        )
                    except InvalidRequest as exc:
                        _write_error(handler, exc.status_code, exc.detail)
                        return
                return await method(handler, token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def optional(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Callable[[F], F]:
        """Allow anonymous access.

        The decorated method receives :class:`~py_oidc_auth.schema.IDToken` or
        ``None`` as an extra argument.

        :param claims: Optional claim constraints (passthrough mode only).
        :param scopes: Space separated scope names.
        :returns: Decorator for Tornado handler methods.
        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        def decorator(method: F) -> F:
            @functools.wraps(method)
            async def wrapper(
                handler: tornado.web.RequestHandler,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                bearer = self._extract_bearer(handler)
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
                return await method(handler, token, *args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    def get_auth_routes(
        self,
        prefix: str = "",
        login: str = "/auth/v2/login",
        callback: str = "/auth/v2/callback",
        token: str = "/auth/v2/token",
        device_flow: Optional[str] = "/auth/v2/device",
        logout: Optional[str] = "/auth/v2/logout",
        userinfo: Optional[str] = "/auth/v2/userinfo",
        jwks: Optional[str] = "/auth/v2/.well-known/jwks.json",
    ) -> List[Tuple[str, Type[tornado.web.RequestHandler], Dict[str, Any]]]:
        """Return Tornado routes implementing the standard auth endpoints.

        The return value is a list of ``(pattern, handler_class, init_kwargs)``
        tuples.

        :param prefix: URL prefix for all routes.
        :param login: Path for login.
        :param callback: Path for callback.
        :param token: Path for token exchange / broker JWT issuance.
        :param device_flow: Path for starting the device flow.
        :param logout: Path for logout.
        :param userinfo: Path for userinfo.
        :param userinfo: Path for userinfo (passthrough mode only).
        :returns: List of Tornado route tuples.
        :raises ValueError: When ``broker_mode=True`` and ``token`` is falsy.

        Request example

        .. code-block:: text

            GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
            Host: app.example.org

        """
        self._validate_broker_config(has_token_endpoint=bool(token))

        auth = self
        routes: List[Tuple[str, Type[tornado.web.RequestHandler], Dict[str, Any]]] = []

        class _BaseHandler(tornado.web.RequestHandler):
            def initialize(self, oidc_auth: TornadoOIDCAuth) -> None:
                self.oidc_auth = oidc_auth

        if login:

            class LoginHandler(_BaseHandler):
                async def get(self) -> None:
                    redirect_uri = self.get_query_argument("redirect_uri", None)
                    prompt = cast(
                        PromptField, self.get_query_argument("prompt", "none")
                    )
                    offline_access = (
                        self.get_query_argument("offline_access", "false").lower()
                        == "true"
                    )
                    scope = self.get_query_argument("scope", None)
                    try:
                        auth_url = await self.oidc_auth.login(
                            redirect_uri=redirect_uri,
                            prompt=prompt,
                            offline_access=offline_access,
                            scope=scope,
                        )
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.redirect(auth_url)

            routes.append((f"{prefix}{login}", LoginHandler, {"oidc_auth": auth}))

        if callback:

            class CallbackHandler(_BaseHandler):
                async def get(self) -> None:
                    code = self.get_query_argument("code", None)
                    state = self.get_query_argument("state", None)
                    try:
                        result = await self.oidc_auth.callback(code=code, state=state)
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(result))

            routes.append((f"{prefix}{callback}", CallbackHandler, {"oidc_auth": auth}))

        if device_flow:

            class DeviceFlowHandler(_BaseHandler):
                async def post(self) -> None:
                    try:
                        result = await self.oidc_auth.device_flow()
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(result.model_dump()))

            routes.append(
                (f"{prefix}{device_flow}", DeviceFlowHandler, {"oidc_auth": auth})
            )

        if token:
            _token_endpoint = f"{prefix}{token}"

            class TokenHandler(_BaseHandler):
                async def post(self) -> None:
                    code = self.get_body_argument("code", None)
                    redirect_uri = self.get_body_argument("redirect_uri", None)
                    refresh_token = self.get_body_argument("refresh-token", None)
                    device_code = self.get_body_argument("device-code", None)
                    code_verifier = self.get_body_argument("code_verifier", None)
                    grant_type = self.get_body_argument("grant_type", None)
                    subject_token = self.get_body_argument("subject_token", None)
                    try:
                        if self.oidc_auth.broker_mode:
                            result = await self.oidc_auth.broker_token(
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
                            result = await self.oidc_auth.token(
                                _token_endpoint,
                                code=code,
                                redirect_uri=redirect_uri,
                                refresh_token=refresh_token,
                                device_code=device_code,
                                code_verifier=code_verifier,
                            )
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(result.model_dump()))

            routes.append((f"{prefix}{token}", TokenHandler, {"oidc_auth": auth}))

        if jwks and auth.broker_mode:

            class JWKSHandler(_BaseHandler):
                async def get(self) -> None:
                    doc = await self.oidc_auth.broker_jwks()
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(doc))

            routes.append((f"{prefix}{jwks}", JWKSHandler, {"oidc_auth": auth}))

        if logout:

            class LogoutHandler(_BaseHandler):
                async def get(self) -> None:
                    post_logout_redirect_uri = self.get_query_argument(
                        "post_logout_redirect_uri", None
                    )
                    target = await self.oidc_auth.logout(post_logout_redirect_uri)
                    self.redirect(target)

            routes.append((f"{prefix}{logout}", LogoutHandler, {"oidc_auth": auth}))

        if userinfo:

            class UserinfoHandler(_BaseHandler):
                @auth.required()
                async def get(self, token_obj: IDToken) -> None:
                    try:
                        result = await self.oidc_auth.userinfo(
                            token_obj, dict(self.request.headers)
                        )
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(result.model_dump()))

            routes.append((f"{prefix}{userinfo}", UserinfoHandler, {"oidc_auth": auth}))

        return routes
