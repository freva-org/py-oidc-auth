"""FastAPI integration for py oidc auth.

The :class:`~py_oidc_auth.fastapi_auth.FastApiOIDCAuth` class provides:

* Dependencies for protected and optional routes
* An :class:`fastapi.APIRouter` with standard authentication endpoints

Install::

    pip install py-oidc-auth[fastapi]
    conda install -c conda-forge py-oidc-fastapi

Basic usage

.. code-block:: python

    from fastapi import FastAPI
    from py_oidc_auth.fastapi_auth import FastApiOIDCAuth

    app = FastAPI()

    auth = FastApiOIDCAuth(
        client_id="my client",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
        client_secret="secret",
        scopes="myscope profile email",
    )

    app.include_router(auth.create_auth_router(prefix="/api"))

    @app.get("/me")
    async def me(token = auth.required()):
        return {"sub": token.sub}

"""

import logging
from enum import Enum
from typing import (
    Annotated,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Union,
)

try:
    from fastapi import (
        APIRouter,
        Depends,
        Form,
        HTTPException,
        Query,
        Request,
        Security,
    )
    from fastapi.responses import RedirectResponse
    from fastapi.security import (
        HTTPAuthorizationCredentials,
        HTTPBearer,
        SecurityScopes,
    )
except ImportError:
    raise ImportError(
        "FastAPI integration requires the 'fastapi' extra. "
        "Install it with: pip install py-oidc-auth[fastapi]"
    ) from None

from .auth_base import OIDCAuth
from .exceptions import InvalidRequest
from .schema import DeviceStartResponse, IDToken, Token, UserInfo

Required: Any = Ellipsis

logger = logging.getLogger(__name__)


class Prompt(str, Enum):
    """Values for the OpenID Connect prompt parameter."""

    none = "none"
    login = "login"
    consent = "consent"
    select_account = "select_account"


class FastApiOIDCAuth(OIDCAuth):
    """Reusable OpenID Connect helper for FastAPI.

    The class extends :class:`~py_oidc_auth.auth_base.OIDCAuth` and adds a
    FastAPI friendly surface.

    You typically:

    * Create an instance once at startup
    * Include :meth:`create_auth_router` in your app
    * Use :meth:`required` and :meth:`optional` as dependencies on routes

    """

    def required(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Any:
        """Return a dependency that enforces authentication.

        The dependency validates the bearer token from the ``Authorization``
        header.
        If validation fails, a FastAPI :class:`fastapi.HTTPException` is raised.

        :param claims: Optional claim constraints. If not provided, the
            constraints from :attr:`~py_oidc_auth.utils.OIDCConfig.claims` are
            used.
        :param scopes: Space separated scope names that the token must contain.
        :returns: A ready to use :func:`fastapi.Security` dependency.

        Example
        -------
        .. code-block:: python

            @app.get("/admin")
            async def admin(token: IDToken = auth.required(scopes="admin")):
                return {"sub": token.sub}

        """
        scope_list = [s.strip() for s in scopes.split() if s.strip()]
        return Security(
            self._create_auth_dependency(
                required=True, claims=claims, scopes=scope_list
            ),
            scopes=scope_list,
        )

    def optional(
        self,
        claims: Optional[Dict[str, Any]] = None,
        scopes: str = "",
    ) -> Any:
        """Return a dependency that accepts anonymous requests.

        When no bearer token is present, or when token validation fails, the
        dependency returns ``None``.

        :param claims: Optional claim constraints.
        :param scopes: Space separated scope names.
        :returns: A ready to use :func:`fastapi.Security` dependency.

        Example
        -------
        .. code-block:: python

            @app.get("/feed")
            async def feed(token: Optional[IDToken] = auth.optional()):
                if token:
                    return {"hello": token.preferred_username}
                return {"hello": "guest"}

        """
        scope_list = [s.strip() for s in scopes.split() if s.strip()]
        return Security(
            self._create_auth_dependency(
                required=False, claims=claims, scopes=scope_list
            ),
            scopes=scope_list,
        )

    def _create_auth_dependency(
        self,
        required: bool = True,
        claims: Optional[Dict[str, Any]] = None,
        scopes: Optional[Sequence[str]] = None,
    ) -> Callable[
        [SecurityScopes, Optional[HTTPAuthorizationCredentials]],
        Awaitable[Optional[IDToken]],
    ]:
        """Create the internal FastAPI dependency that performs token validation."""
        effective_claims = claims if claims is not None else self.config.claims
        required_scopes = set(
            scopes if scopes is not None else self.config.scopes or []
        )

        async def dependency(
            security_scopes: SecurityScopes,
            authorization_credentials: Optional[
                HTTPAuthorizationCredentials
            ] = Depends(HTTPBearer(auto_error=required)),
        ) -> Optional[IDToken]:
            await self._ensure_auth_initialized()
            token = (
                None
                if authorization_credentials is None
                else authorization_credentials.credentials
            )
            try:
                return await self._get_token(
                    token,
                    required_scopes=required_scopes,
                    effective_claims=effective_claims,
                )
            except InvalidRequest as error:
                if required:
                    raise HTTPException(
                        status_code=error.status_code, detail=error.detail
                    )
            return None

        return dependency

    def create_auth_router(
        self,
        prefix: str = "",
        login: str = "/auth/v2/login",
        callback: str = "/auth/v2/callback",
        token: str = "/auth/v2/token",
        device_flow: Optional[str] = "/auth/v2/device",
        logout: Optional[str] = "/auth/v2/logout",
        userinfo: Optional[str] = "/auth/v2/userinfo",
        tags: Optional[List[Union[str, Enum]]] = None,
    ) -> "APIRouter":
        """Build an :class:`fastapi.APIRouter` with standard auth endpoints.

        Each route can be disabled by passing ``None`` for the corresponding
        path.

        :param prefix: URL prefix for all routes.
        :param login: Login route path.
        :param callback: Callback route path.
        :param token: Token route path.
        :param device_flow: Device flow start route path.
        :param logout: Logout route path.
        :param userinfo: Userinfo route path.
        :param tags: OpenAPI tags for all routes.
        :returns: A router that can be included via ``app.include_router``.

        Request examples
        ----------------

        Login

        .. code-block:: text

            GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
            Host: app.example.org

        Callback

        .. code-block:: text

            GET /auth/v2/callback?code=abc&state=xyz HTTP/1.1
            Host: app.example.org

        Token exchange

        .. code-block:: text

            POST /auth/v2/token HTTP/1.1
            Host: app.example.org
            Content-Type: application/x-www-form-urlencoded

            code=abc&redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback

        Userinfo

        .. code-block:: text

            GET /auth/v2/userinfo HTTP/1.1
            Host: app.example.org
            Authorization: Bearer <access token>

        """
        router = APIRouter(prefix=prefix, tags=tags or ["Authentication"])
        auth_dependency = self._create_auth_dependency()
        _login_func = self.login
        _callback_func = self.callback
        _deviceflow_func = self.device_flow
        _token_func = self.token
        _logout_func = self.logout
        _userinfo_func = self.userinfo

        if login:

            @router.get(
                login,
                response_class=RedirectResponse,
                responses={
                    307: {
                        "description": "Redirect to the identity provider login page.",
                    },
                    400: {"description": "Missing redirect_uri."},
                },
            )
            async def _login(
                redirect_uri: Annotated[
                    Optional[str],
                    Query(
                        title="Redirect URI",
                        description="URI to redirect back to after login.",
                        examples=["http://localhost:8080/callback"],
                    ),
                ] = None,
                prompt: Annotated[
                    Prompt,
                    Query(
                        title="Prompt",
                        description="OpenID Connect prompt parameter.",
                    ),
                ] = Prompt.none,
                offline_access: Annotated[
                    bool,
                    Query(
                        title="Request offline token",
                        description="Include offline_access scope.",
                    ),
                ] = False,
                scope: Annotated[
                    Optional[str],
                    Query(title="Scope", description="Requested scopes."),
                ] = None,
            ) -> RedirectResponse:
                """Initiate the authorization code flow and redirect to the provider."""
                try:
                    auth_url = await _login_func(
                        redirect_uri=redirect_uri,
                        prompt=prompt.value,
                        offline_access=offline_access,
                        scope=scope,
                    )
                except InvalidRequest as error:
                    raise HTTPException(
                        status_code=error.status_code, detail=error.detail
                    )

                return RedirectResponse(auth_url)

        if callback:

            @router.get(
                callback,
                responses={
                    200: {"description": "Token exchange successful."},
                    400: {"description": "Missing or invalid code or state."},
                },
            )
            async def _callback(
                code: Annotated[Optional[str], Query()] = None,
                state: Annotated[Optional[str], Query()] = None,
            ) -> Dict[str, Union[str, int]]:
                """Handle the callback from the provider."""
                try:
                    return await _callback_func(code=code, state=state)
                except InvalidRequest as error:
                    raise HTTPException(
                        status_code=error.status_code, detail=error.detail
                    )

        if device_flow:

            @router.post(device_flow, response_model=DeviceStartResponse)
            async def _device_flow() -> DeviceStartResponse:
                """Start the device authorization flow."""
                try:
                    return await _deviceflow_func()
                except InvalidRequest as error:
                    raise HTTPException(
                        status_code=error.status_code, detail=error.detail
                    )

        if token:

            @router.post(token)
            async def _fetch_or_refresh_token(
                code: Annotated[Optional[str], Form()] = None,
                redirect_uri: Annotated[Optional[str], Form()] = None,
                refresh_token: Annotated[
                    Optional[str], Form(alias="refresh-token")
                ] = None,
                device_code: Annotated[
                    Optional[str], Form(alias="device-code")
                ] = None,
                code_verifier: Optional[str] = Form(None),
            ) -> Token:
                """Exchange, refresh, or poll for an OAuth token."""
                try:
                    return await _token_func(
                        f"{prefix}/{token}",
                        code=code,
                        redirect_uri=redirect_uri,
                        refresh_token=refresh_token,
                        device_code=device_code,
                        code_verifier=code_verifier,
                    )
                except InvalidRequest as error:
                    raise HTTPException(
                        status_code=error.status_code, detail=error.detail
                    )

        if logout:

            @router.get(
                logout,
                responses={
                    307: {"description": "Redirect to post logout URI."},
                },
            )
            async def _logout(
                post_logout_redirect_uri: Annotated[
                    Optional[str],
                    Query(title="Post logout redirect URI"),
                ] = None,
            ) -> RedirectResponse:
                """Redirect to the provider end session endpoint when available."""
                return RedirectResponse(
                    await _logout_func(post_logout_redirect_uri)
                )

        if userinfo:

            @router.get(userinfo, tags=["Authentication"])
            async def _userinfo(
                id_token: IDToken = Security(auth_dependency),
                request: Request = Required,
            ) -> UserInfo:
                """Return user profile information for the current request."""
                try:
                    return await _userinfo_func(id_token, dict(request.headers))
                except InvalidRequest as error:
                    logger.exception(error)
                    raise HTTPException(
                        status_code=error.status_code, detail=error.detail
                    )

        return router
