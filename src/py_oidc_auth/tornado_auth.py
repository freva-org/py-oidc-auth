"""Tornado integration for py oidc auth.

Tornado supports asyncio based request handlers.
This adapter calls the async base implementation directly.

Install

.. code-block:: text

    pip install py-oidc-auth[tornado]

Usage

.. code-block:: python

    import tornado.web
    import tornado.ioloop
    from py_oidc_auth.tornado_auth import TornadoOIDCAuth

    auth = TornadoOIDCAuth(
        client_id="my client",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
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
    Use :meth:`get_auth_routes` to add standard auth endpoints.

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
                credentials = self._extract_bearer(handler)
                try:
                    token = await self._get_token(
                        credentials,
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

        :param claims: Optional claim constraints.
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
                credentials = self._extract_bearer(handler)
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
    ) -> List[Tuple[str, Type[tornado.web.RequestHandler], Dict[str, Any]]]:
        """Return Tornado routes implementing the standard auth endpoints.

        The return value is a list of ``(pattern, handler_class, init_kwargs)``
        tuples.

        :param prefix: URL prefix for all routes.
        :param login: Path for login.
        :param callback: Path for callback.
        :param token: Path for token exchange and refresh.
        :param device_flow: Path for starting the device flow.
        :param logout: Path for logout.
        :param userinfo: Path for userinfo.
        :returns: List of Tornado route tuples.

        Request example

        .. code-block:: text

            GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
            Host: app.example.org

        """
        auth = self
        routes: List[
            Tuple[str, Type[tornado.web.RequestHandler], Dict[str, Any]]
        ] = []

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
                        result = await self.oidc_auth.callback(
                            code=code, state=state
                        )
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(result))

            routes.append(
                (f"{prefix}{callback}", CallbackHandler, {"oidc_auth": auth})
            )

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

            class TokenHandler(_BaseHandler):
                async def post(self) -> None:
                    code = self.get_body_argument("code", None)
                    redirect_uri = self.get_body_argument("redirect_uri", None)
                    refresh_token = self.get_body_argument("refresh-token", None)
                    device_code = self.get_body_argument("device-code", None)
                    code_verifier = self.get_body_argument("code_verifier", None)
                    try:
                        result = await self.oidc_auth.token(
                            f"{prefix}/{token}",
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

        if logout:

            class LogoutHandler(_BaseHandler):
                async def get(self) -> None:
                    post_logout_redirect_uri = self.get_query_argument(
                        "post_logout_redirect_uri", None
                    )
                    target = await self.oidc_auth.logout(post_logout_redirect_uri)
                    self.redirect(target)

            routes.append(
                (f"{prefix}{logout}", LogoutHandler, {"oidc_auth": auth})
            )

        if userinfo:

            class UserinfoHandler(_BaseHandler):
                async def get(self) -> None:
                    credentials = TornadoOIDCAuth._extract_bearer(self)
                    try:
                        token_obj = await self.oidc_auth._get_token(credentials)
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    try:
                        result = await self.oidc_auth.userinfo(
                            token_obj, dict(self.request.headers)
                        )
                    except InvalidRequest as exc:
                        _write_error(self, exc.status_code, exc.detail)
                        return
                    self.set_header("Content-Type", "application/json")
                    self.write(json.dumps(result.model_dump()))

            routes.append(
                (f"{prefix}{userinfo}", UserinfoHandler, {"oidc_auth": auth})
            )

        return routes
