"""Litestar integration for py oidc auth.

Litestar is an async framework with dependency injection.
This adapter integrates authentication using Litestar's :class:`litestar.di.Provide`.

Install::

    pip install py-oidc-auth[litestar]
    conda install -c conda-forge py-oidc-auth-litestar

Usage

.. code-block:: python

    from litestar import Litestar, get
    from py_oidc_auth.litestar_auth import LitestarOIDCAuth
    from py_oidc_auth.schema import IDToken

    auth = LitestarOIDCAuth(
        client_id="my client",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
        scopes="myscope profile email",
    )

    @get("/protected", dependencies={"token": auth.required()})
    async def protected(token: IDToken) -> dict:
        return {"sub": token.sub}

    app = Litestar(route_handlers=[auth.create_auth_router(prefix="/api"), protected])

"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Union, cast

try:
    from litestar import Request, Router, get, post
    from litestar.di import Provide
    from litestar.exceptions import (
        HTTPException,
        NotAuthorizedException,
        PermissionDeniedException,
    )
    from litestar.response import Redirect
except ImportError:  # pragma: no cover
    raise ImportError(
        "Litestar integration requires the 'litestar' extra. "
        "Install it with: pip install py-oidc-auth[litestar]"
    ) from None

from .auth_base import OIDCAuth
from .exceptions import InvalidRequest
from .schema import IDToken, PromptField

logger = logging.getLogger(__name__)


LitestarRequest = Request[Any, Any, Any]


def _map_exception(exc: InvalidRequest) -> HTTPException:
    """Map :class:`InvalidRequest` to a Litestar exception."""
    if exc.status_code == 401:
        return NotAuthorizedException(detail=exc.detail)
    if exc.status_code == 403:
        return PermissionDeniedException(detail=exc.detail)
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


class LitestarOIDCAuth(OIDCAuth):
    """Reusable OpenID Connect helper for Litestar.

    The public surface is:

    * :meth:`required` and :meth:`optional` for dependency injection
    * :meth:`create_auth_router` for standard auth routes

    """

    @staticmethod
    def _extract_bearer(request: LitestarRequest) -> Optional[str]:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None

    def required(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Provide:
        """Return a :class:`litestar.di.Provide` that enforces authentication.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: Provide instance usable in ``dependencies``.

        Example
        -------
        .. code-block:: python

            @get("/protected", dependencies={"token": auth.required(scopes="admin")})
            async def protected(token: IDToken) -> dict:
                return {"sub": token.sub}

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        async def provide_token(request: LitestarRequest) -> IDToken:
            credentials = self._extract_bearer(request)
            try:
                return await self._get_token(
                    credentials,
                    required_scopes=scope_set or None,
                    effective_claims=effective_claims,
                )
            except InvalidRequest as exc:
                raise _map_exception(exc)

        return Provide(provide_token, sync_to_thread=False)

    def optional(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Provide:
        """Return a :class:`litestar.di.Provide` that allows anonymous access.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: Provide instance.

        """
        scope_set = set(s.strip() for s in scopes.split() if s.strip())
        effective_claims = claims if claims is not None else self.config.claims

        async def provide_token(request: LitestarRequest) -> Optional[IDToken]:
            credentials = self._extract_bearer(request)
            if not credentials:
                return None
            try:
                return await self._get_token(
                    credentials,
                    required_scopes=scope_set or None,
                    effective_claims=effective_claims,
                )
            except InvalidRequest:
                return None

        return Provide(provide_token, sync_to_thread=False)

    def create_auth_router(
        self,
        prefix: str = "",
        login: str = "/auth/v2/login",
        callback: str = "/auth/v2/callback",
        token: str = "/auth/v2/token",
        device_flow: Optional[str] = "/auth/v2/device",
        logout: Optional[str] = "/auth/v2/logout",
        userinfo: Optional[str] = "/auth/v2/userinfo",
    ) -> Router:
        """Build a Litestar :class:`litestar.Router` with standard auth routes.

        :param prefix: URL prefix for all routes.
        :param login: Path for login.
        :param callback: Path for callback.
        :param token: Path for token exchange and refresh.
        :param device_flow: Path for starting the device flow.
        :param logout: Path for logout.
        :param userinfo: Path for userinfo.
        :returns: Router instance.

        Request example
        ---------------

        .. code-block:: text

            GET /auth/v2/userinfo HTTP/1.1
            Host: app.example.org
            Authorization: Bearer <access token>

        """
        auth = self
        handlers = []

        if login:

            @get(login)
            async def _login(request: LitestarRequest) -> Redirect:
                redirect_uri = request.query_params.get("redirect_uri")
                prompt = cast(
                    PromptField, request.query_params.get("prompt", "none")
                )
                offline_access = (
                    request.query_params.get("offline_access", "false").lower()
                    == "true"
                )
                scope = request.query_params.get("scope")
                try:
                    auth_url = await auth.login(
                        redirect_uri=redirect_uri,
                        prompt=prompt,
                        offline_access=offline_access,
                        scope=scope,
                    )
                except InvalidRequest as exc:
                    raise _map_exception(exc)
                return Redirect(path=auth_url)

            handlers.append(_login)

        if callback:

            @get(callback)
            async def _callback(
                request: LitestarRequest,
            ) -> Dict[str, Union[str, int]]:
                code = request.query_params.get("code")
                state = request.query_params.get("state")
                try:
                    return await auth.callback(code=code, state=state)
                except InvalidRequest as exc:
                    raise _map_exception(exc)

            handlers.append(_callback)

        if device_flow:

            @post(device_flow, status_code=200)
            async def _device_flow() -> Dict[str, Any]:
                try:
                    result = await auth.device_flow()
                    return result.model_dump()
                except InvalidRequest as exc:
                    raise _map_exception(exc)

            handlers.append(_device_flow)

        if token:

            @post(token, status_code=200)
            async def _token(request: LitestarRequest) -> Dict[str, Any]:
                form = await request.form()
                code = form.get("code")
                redirect_uri = form.get("redirect_uri")
                refresh_token = form.get("refresh-token")
                device_code = form.get("device-code")
                code_verifier = form.get("code_verifier")
                try:
                    result = await auth.token(
                        f"{prefix}/{token}",
                        code=code,
                        redirect_uri=redirect_uri,
                        refresh_token=refresh_token,
                        device_code=device_code,
                        code_verifier=code_verifier,
                    )
                    return result.model_dump()
                except InvalidRequest as exc:
                    raise _map_exception(exc)

            handlers.append(_token)

        if logout:

            @get(logout)
            async def _logout(request: LitestarRequest) -> Redirect:
                post_logout_redirect_uri = request.query_params.get(
                    "post_logout_redirect_uri"
                )
                target = await auth.logout(post_logout_redirect_uri)
                return Redirect(path=target)

            handlers.append(_logout)

        if userinfo:
            required_dep = self.required()

            @get(userinfo, dependencies={"token": required_dep})
            async def _userinfo(
                request: LitestarRequest, token: IDToken
            ) -> Dict[str, Any]:
                try:
                    result = await auth.userinfo(token, dict(request.headers))
                    return result.model_dump()
                except InvalidRequest as exc:
                    raise _map_exception(exc)

            handlers.append(_userinfo)

        return Router(path=prefix, route_handlers=handlers)
