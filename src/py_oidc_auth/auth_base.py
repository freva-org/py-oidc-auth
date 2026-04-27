"""Framework independent OpenID Connect client.

The :class:`~py_oidc_auth.auth_base.OIDCAuth` class implements the common
OpenID Connect and OAuth 2 flows used by the framework adapters.

It is intentionally framework independent.
The FastAPI, Flask, Quart, Tornado, Litestar, and Django integrations expose
HTTP endpoints and decorators that call into this class.

Supported flows

* Authorization code flow with PKCE
* Refresh token flow
* Device authorization flow
* Userinfo lookup
* Provider initiated logout (end session)

Quick start

.. code-block:: python

    from py_oidc_auth.auth_base import OIDCAuth

    auth = OIDCAuth(
        client_id="my client",
        client_secret="secret",
        discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
        scopes="openid profile email",
        offline_access=True,
        broker_mode=True,
        broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
        broker_audience="myapp-api",
        trusted_issuers=["https://other-instance.example.org"],
    )

    login_url = await auth.login(
        redirect_uri="https://app.example.org/auth/callback",
        prompt="login",
        offline_access=True,
    )

    token_payload = await auth.callback(code="...", state="...")

The value returned by :meth:`OIDCAuth.login` is a URL that you redirect the
browser to.
The code and state values are sent back to your callback endpoint by the
identity provider.

"""

import asyncio
import base64
import datetime
import hashlib
import json
import logging
import secrets
from typing import Any, Dict, Optional, Set, Union, cast
from urllib.parse import urlencode, urljoin

import httpx
import jwt as pyjwt

from .broker.issuer import TokenBroker
from .broker.store import BrokerStore, create_broker_store
from .exceptions import InvalidRequest
from .schema import (
    DeviceStartResponse,
    IDToken,
    Payload,
    PromptField,
    Token,
    UserInfo,
)
from .token_validation import TokenVerifier
from .utils import (
    OIDCConfig,
    get_username,
    oidc_request,
    process_payload,
    query_user,
    token_field_matches,
)

logger = logging.getLogger(__name__)


def _set_request_header(
    client_id: str,
    client_secret: Optional[str],
    data: Dict[str, str],
    header: Dict[str, str],
) -> None:
    """Populate request headers for token and device requests.

    Confidential clients usually authenticate to the token endpoint via HTTP
    Basic authentication.
    Public clients do not have a client secret and therefore send the
    client id in the form body.

    :param client_id: OAuth client identifier.
    :param client_secret: Client secret for confidential clients.
    :param data: Form data that will be sent to the provider.
    :param header: Header mapping that will be sent to the provider.
    """
    header["Content-Type"] = "application/x-www-form-urlencoded"
    if client_secret:
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        header["Authorization"] = f"Basic {basic}"
    else:
        data["client_id"] = client_id


class OIDCAuth:
    """Async OIDC client with a minimal, stable API.

    Instances of this class hold configuration and a lazy initialized
    :class:`~py_oidc_auth.token_validation.TokenVerifier`.

    :param client_id: OIDC client identifier.
    :param discovery_url: URL of the provider discovery document.
    :param client_secret: Client secret for confidential clients.
    :param scopes: Default scopes as a space separated string.
    :param proxy: Public base URL of your application.
    :param claims: Optional claim constraints for token validation.
    :param audience: Optional audience constraints for token validation.
    :param offline_access: If true, include ``offline_access``
                           in scope to request a `refresh token`.
    :param timeout_sec: HTTP timeout for discovery and provider calls.
    :param jwks_uri: Use this jwks uri instead of the one provided by the
                     discovery-url
    :param issuer: Use this issuer instead of the one provided by the
                   disovery-url
    :param broker_mode: Enable token broker mode.  When ``True``, the library
        mints its own RS256-signed JWTs instead of passing IDP tokens through.
        ``required()`` and ``optional()`` verify against the broker JWKS.
        A token endpoint **must** be configured in ``create_auth_router`` when
        broker mode is enabled.
    :param broker_store_url: Connection URL for the broker storage backend.
        Defaults to a local SQLite file.  Supported schemes:
        ``memory://``, ``mongodb://``, ``sqlite+aiosqlite:///``,
        ``postgresql+asyncpg://``, ``mysql+aiomysql://``.
    :param broker_store_obj: A pre-instantiated
        :class:`~py_oidc_auth.broker.store.BrokerStore`. Use this when you want
        to share an existing database connection rather than have the library
        create its own. Takes precedence over ``broker_store_url``. For
        example, pass a :class:`~py_oidc_auth.broker.store.MongoDBBrokerStore`
        built from your application's existing Motor/pymongo client, or a
        :class:`~py_oidc_auth.broker.store.SQLAlchemyBrokerStore` built from
        your existing async engine.
    :param broker_audience: ``aud`` claim written into minted JWTs.
        Defaults to ``py-oidc-auth``.
    :param trusted_issuers: List of peer instance base URLs whose JWTs are
        accepted for cross-instance federation.
    :param broker_jwks_path: Path appended to peer URLs when fetching JWKS.

    Example
    -------
    .. code-block:: python

        from py_oidc_auth import OIDCAuth

        auth = OIDCAuth(
            client_id="my client",
            discovery_url="https://idp.example.org/.well-known/openid-configuration",
            client_secret="secret",
            scopes="myscope profile email",
            appname="my-app",
            audience="my-aud",
            broker_mode=True,
            broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
            broker_audience="myapp-api",
            trusted_issuers=["https://other-instance.example.org"],
        )

    With an existing database connection:

    .. code-block:: python


        from pymongo import AsyncMongoClient
        from py_oidc_auth import OIDCAuth, MongoDBBrokerStore

        mongo_client = AsyncMongoClient("mongodb://user:pass@host")
        mongo_store = MongoDBBrokerStore(db=mongo_client["my_app"])
        auth = OIDCAuth(
            client_id="my client",
            discovery_url="https://idp.example.org/.well-known/openid-configuration",
            client_secret="secret",
            scopes="myscope profile email",
            appname="my-app",
            audience="my-aud",
            broker_mode=True,
            broker_store_obj=mongo_store,
            broker_audience="myapp-api",
            trusted_issuers=["https://other-instance.example.org"],
        )


    """

    def __init__(
        self,
        client_id: str = "",
        discovery_url: str = "",
        client_secret: Optional[str] = None,
        scopes: str = "profile email",
        audience: Optional[str] = None,
        appname: str = "py-oidc-auth",
        proxy: str = "",
        claims: Optional[Dict[str, Any]] = None,
        offline_access: bool = True,
        timeout_sec: int = 10,
        jwks_uri: Optional[str] = None,
        issuer: Optional[str] = None,
        broker_mode: bool = False,
        broker_store_url: Optional[str] = None,
        broker_store_obj: Optional[BrokerStore] = None,
        broker_audience: str = "py-oidc-auth",
        trusted_issuers: Optional[list[str]] = None,
        broker_jwks_path: str = "/auth/v2/.well-known/jwks.json",
    ) -> None:
        self._lock = asyncio.Lock()
        self.config = OIDCConfig(
            client_id,
            discovery_url=discovery_url,
            client_secret=client_secret,
            scopes=[s for s in scopes.split() if s.strip()],
            proxy=proxy,
            claims=claims,
            audience=audience,
            timeout=httpx.Timeout(timeout_sec),
            offline_access=offline_access,
        )
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._verifier: Optional[TokenVerifier] = None

        # Broker mode
        self.broker_mode = broker_mode
        self.appname = appname
        self._broker_store_url = broker_store_url
        self._broker_store_obj = broker_store_obj
        self.broker_audience = broker_audience
        self.trusted_issuers: list[str] = trusted_issuers or []
        self.broker_jwks_path = broker_jwks_path
        self._broker: Optional["TokenBroker"] = None
        self._broker_lock = asyncio.Lock()

    async def _ensure_auth_initialized(self) -> None:
        """Load the discovery document and prepare token validation.

        The discovery document is fetched through
        :attr:`py_oidc_auth.utils.OIDCConfig.oidc_overview`.

        The token verifier is created lazily because not all deployments need
        token validation.
        """
        if self._verifier is not None or not self.config.discovery_url:
            return
        async with self._lock:
            try:
                jwks_uri = cast(
                    str, self._jwks_uri or self.config.oidc_overview["jwks_uri"]
                )
                issuer = cast(
                    Optional[str],
                    self._issuer or self.config.oidc_overview.get("issuer"),
                )
                self._verifier = TokenVerifier(
                    jwks_uri=jwks_uri,
                    issuer=issuer,
                    audience=self.config.audience,
                    timeout=self.config.timeout,
                )
                logger.info("OIDC initialized from %s", self.config.discovery_url)
            except Exception as exc:
                logger.exception("Failed to initialise OIDC: %s", exc)

    async def _ensure_broker_ready(self) -> "TokenBroker":
        """Lazily initialise and return the :class:`~py_oidc_auth.broker.issuer.TokenBroker`."""
        if self._broker is not None:
            return self._broker
        async with self._broker_lock:
            store: BrokerStore = self._broker_store_obj or create_broker_store(
                self._broker_store_url, self.appname
            )
            broker = TokenBroker(
                store=store,
                issuer=self.config.proxy or self.broker_audience,
                audience=self.broker_audience,
                trusted_issuers=self.trusted_issuers,
                jwks_path=self.broker_jwks_path,
            )
            await broker.setup()
            self._broker = broker
        return self._broker

    def _validate_broker_config(self, has_token_endpoint: bool) -> None:
        """Validate broker/token-endpoint consistency.

        Call this from every framework adapter's router/blueprint registration
        method (``create_auth_router``, ``create_blueprint``, etc.) before
        registering any routes.  This ensures the check fires regardless of
        which framework is in use.

        :param has_token_endpoint: ``True`` if the adapter is registering a
            token endpoint.
        :raises ValueError: When ``broker_mode=True`` and no token endpoint is
            configured — clients would have no way to obtain broker JWTs.

        The reverse case (token endpoint without broker mode) is logged as a
        warning rather than an error because it is a valid configuration for
        pure passthrough deployments, albeit one that foregoes audience
        restriction on IDP tokens.
        """
        if self.broker_mode and not has_token_endpoint:
            raise ValueError(
                "broker_mode=True requires a token endpoint. "
                "Configure one in your framework adapter's router/blueprint "
                "registration call."
            )
        if has_token_endpoint and not self.broker_mode:
            logger.warning(
                "A token endpoint is configured but broker_mode=False. "
                "Clients will receive raw IDP tokens without audience "
                "restriction. Consider setting broker_mode=True."
            )

    async def make_oidc_request(
        self,
        method: str,
        endpoint_key: str,
        *,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Call a provider endpoint from the discovery document.

        The discovery document contains URLs such as ``token_endpoint`` and
        ``device_authorization_endpoint``.

        :param method: HTTP method, for example ``POST``.
        :param endpoint_key: Key in the discovery document.
        :param data: Optional form data.
        :param headers: Optional request headers.
        :returns: JSON response decoded into a dict.
        :raises InvalidRequest: If the endpoint is missing or the request fails.

        Example
        -------
        .. code-block:: python

            jwks = await auth.make_oidc_request("GET", "jwks_uri")

        """
        await self._ensure_auth_initialized()
        url = cast(str, self.config.oidc_overview.get(endpoint_key))
        if not url:
            raise InvalidRequest(
                status_code=502,
                detail=f"OIDC endpoint '{endpoint_key}' not found in discovery.",
            )
        return await oidc_request(
            url,
            method,
            data=data,
            headers=headers,
            timeout=self.config.timeout,
        )

    async def _get_token(
        self,
        authorization_credentials: Optional[str],
        required_scopes: Optional[Set[str]] = None,
        effective_claims: Optional[Dict[str, Any]] = None,
    ) -> IDToken:
        """Validate a bearer token and return it as an :class:`IDToken`.

        Framework adapters call this method.

        :param authorization_credentials: Raw JWT without the ``Bearer`` prefix.
        :param required_scopes: Optional set of scopes that must be granted.
        :param effective_claims: Optional claim constraints.
        :returns: The decoded and verified token.
        :raises InvalidRequest: If validation fails.
        """
        await self._ensure_auth_initialized()

        if self._verifier is None:
            raise InvalidRequest(
                status_code=503,
                detail="OIDC server unavailable, cannot validate token.",
            )
        if authorization_credentials is None:
            raise InvalidRequest(status_code=401, detail="Not authenticated")

        try:
            token = await self._verifier.verify(authorization_credentials)

            if required_scopes:
                granted = set((token.scope or "").split())
                missing_scopes = required_scopes - granted
                if missing_scopes:
                    raise InvalidRequest(
                        403,
                        detail=(
                            "Token missing required scopes: "
                            f"{', '.join(sorted(missing_scopes))}"
                        ),
                    )

            if effective_claims and not token_field_matches(
                authorization_credentials,
                claims=effective_claims,
            ):
                raise InvalidRequest(
                    status_code=401,
                    detail="Insufficient permissions based on token claims.",
                )
            return token
        except (pyjwt.InvalidTokenError, pyjwt.ExpiredSignatureError):
            raise InvalidRequest(401, detail="Invalid token")

    async def login(
        self,
        redirect_uri: Optional[str],
        prompt: PromptField,
        offline_access: bool = False,
        scope: Optional[str] = None,
    ) -> str:
        """Create the authorization URL for the authorization code flow.

        This method generates a URL for the provider authorization endpoint.
        It includes PKCE parameters and stores state information in the
        ``state`` parameter.

        :param redirect_uri: Absolute URL of your callback endpoint.
        :param prompt: Provider prompt parameter.
        :param offline_access: If true, include ``offline_access`` in scope.
        :param scope: Optional scope override.
        :returns: URL to redirect the browser to.
        :raises InvalidRequest: If required configuration is missing.

        Example
        -------
        .. code-block:: python

            url = await auth.login(
                redirect_uri="https://app.example.org/auth/callback",
                prompt="login",
                offline_access=True,
            )

        Request example
        ---------------

        .. code-block:: text

            GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fauth%2Fcallback HTTP/1.1
            Host: app.example.org

        """
        if not redirect_uri:
            raise InvalidRequest(status_code=400, detail="Missing redirect_uri")
        await self._ensure_auth_initialized()
        scope = scope or ""
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        state = f"{secrets.token_urlsafe(16)}|{redirect_uri}|{code_verifier}"
        nonce = secrets.token_urlsafe(16)
        scopes_list = (
            [s.strip() for s in scope.split() if s.strip()] or self.config.scopes or []
        )
        scopes_list += ["offline_access"] if offline_access else []
        query = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(set(scopes_list + ["openid"])),
            "state": state,
            "nonce": nonce,
            "prompt": prompt.replace("none", ""),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        query = {k: v for k, v in query.items() if v}
        return (
            f"{self.config.oidc_overview['authorization_endpoint']}?{urlencode(query)}"
        )

    async def callback(
        self,
        code: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Union[str, int]]:
        """Handle the callback from the authorization code flow.

        Providers call your callback endpoint with query parameters ``code``
        and ``state``.
        This method exchanges the code for tokens by calling the provider
        token endpoint.

        :param code: Authorization code from the provider.
        :param state: Opaque state created by :meth:`login`.
        :returns: Raw JSON response from the token endpoint.
        :raises InvalidRequest: If inputs are missing or the exchange fails.

        Request example
        ----------------
        .. code-block:: text

            GET /auth/v2/callback?code=abc&state=xyz HTTP/1.1
            Host: app.example.org

        """
        if not code or not state:
            raise InvalidRequest(400, detail="Missing code or state")
        try:
            _, redirect_uri, code_verifier = state.split("|", 2)
        except ValueError:
            raise InvalidRequest(400, detail="Invalid state format")

        method = self.broker_token if self.broker_mode else self.token
        token = await method(
            redirect_uri,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        return token.model_dump()

    async def device_flow(self) -> DeviceStartResponse:
        """Start the OAuth 2 device authorization flow.

        This is useful for devices without a browser.
        The provider returns a user code and a verification URI.
        The user visits the URI, enters the code, and authorizes the device.

        :returns: Device authorization information.
        :raises InvalidRequest: If the provider response is malformed.

        Request example
        ---------------
        .. code-block:: text

            POST /auth/v2/device HTTP/1.1
            Host: app.example.org
            Content-Type: application/x-www-form-urlencoded
            Content-Length: 0

        """
        scopes = self.config.scopes or [] + ["openid"]
        scopes += ["offline_access"] if self.config.offline_access else []
        data: Dict[str, str] = {"scope": " ".join(set(scopes))}
        headers: Dict[str, str] = {}
        _set_request_header(
            self.config.client_id, self.config.client_secret, data, headers
        )
        js = await self.make_oidc_request(
            "POST",
            "device_authorization_endpoint",
            data=data,
            headers=headers,
        )
        for k in ("device_code", "user_code", "verification_uri", "expires_in"):
            if k not in js:
                raise InvalidRequest(
                    502,
                    detail=f"upstream_malformed_response, missing: {k}",
                )
        return DeviceStartResponse(
            device_code=js["device_code"],
            user_code=js["user_code"],
            verification_uri=js["verification_uri"],
            verification_uri_complete=js.get("verification_uri_complete"),
            expires_in=int(js["expires_in"]),
            interval=int(js.get("interval", 5)),
        )

    async def token(
        self,
        endpoint: str,
        code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        refresh_token: Optional[str] = None,
        device_code: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> Token:
        """Exchange, refresh, or poll for an access token.

        Exactly one of ``code``, ``refresh_token``, or ``device_code`` must be
        provided.

        :param endpoint: Local endpoint path used to compute a default
            redirect URI when exchanging an authorization code.
        :param code: Authorization code.
        :param redirect_uri: Redirect URI to send to the token endpoint.
        :param refresh_token: Refresh token for renewing access.
        :param device_code: Device code for polling in the device flow.
        :param code_verifier: PKCE verifier used during the login step.
        :returns: Parsed :class:`~py_oidc_auth.schema.Token`.
        :raises InvalidRequest: If inputs are missing or the provider call fails.

        Request examples
        ----------------
        Authorization code exchange

        .. code-block:: text

            POST /auth/v2/token HTTP/1.1
            Host: app.example.org
            Content-Type: application/x-www-form-urlencoded

            code=abc&redirect_uri=https%3A%2F%2Fapp.example.org%2Fauth%2Fcallback&code_verifier=xyz

        Refresh token

        .. code-block:: text

            POST /auth/v2/token HTTP/1.1
            Host: app.example.org
            Content-Type: application/x-www-form-urlencoded

            refresh_token=ref

        Device polling

        .. code-block:: text

            POST /auth/v2/token HTTP/1.1
            Host: app.example.org
            Content-Type: application/x-www-form-urlencoded

            device_code=device

        """
        data: Dict[str, str] = {}
        headers: Dict[str, str] = {}
        if code:
            data["redirect_uri"] = redirect_uri or urljoin(self.config.proxy, endpoint)
            data["grant_type"] = "authorization_code"
            data["code"] = code
            if code_verifier:
                data["code_verifier"] = code_verifier
        elif refresh_token:
            data["grant_type"] = "refresh_token"
            data["refresh_token"] = refresh_token
        elif device_code:
            data["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code"
            data["device_code"] = device_code
        else:
            raise InvalidRequest(400, detail="Missing (device) code or refresh_token")

        _set_request_header(
            self.config.client_id, self.config.client_secret, data, headers
        )
        token_data = await self.make_oidc_request(
            "POST",
            "token_endpoint",
            data={k: v for k, v in data.items() if v},
            headers=headers,
        )

        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        expires_at = (
            token_data.get("exp")
            or token_data.get("expires")
            or token_data.get("expires_at")
            or now + token_data.get("expires_in", 180)
        )
        refresh_expires_at = (
            token_data.get("refresh_exp")
            or token_data.get("refresh_expires")
            or token_data.get("refresh_expires_at")
            or now + token_data.get("refresh_expires_in", 180)
        )
        try:
            return Token(
                access_token=token_data["access_token"],
                token_type=token_data["token_type"],
                expires=int(expires_at),
                refresh_token=token_data["refresh_token"],
                refresh_expires=int(refresh_expires_at),
                scope=token_data["scope"],
            )
        except KeyError:
            raise InvalidRequest(400, detail="Token creation failed.")

    async def logout(self, post_logout_redirect_uri: Optional[str]) -> str:
        """Create a provider logout redirect target.

        If the provider advertises an ``end_session_endpoint`` in the discovery
        document, the returned URL points to that endpoint.
        Otherwise the method returns the local ``post_logout_redirect_uri`` or
        ``/``.

        :param post_logout_redirect_uri: Local URI to redirect to after logout.
        :returns: Redirect target URL.

        Request example

        .. code-block:: text

            GET /auth/v2/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.org HTTP/1.1
            Host: app.example.org

        """
        await self._ensure_auth_initialized()
        redirect_target = post_logout_redirect_uri or "/"
        end_session = self.config.oidc_overview.get("end_session_endpoint")

        if end_session:
            params: Dict[str, str] = {"client_id": self.config.client_id}
            if post_logout_redirect_uri:
                params["post_logout_redirect_uri"] = post_logout_redirect_uri
            redirect_target = f"{end_session}?{urlencode(params)}"
        else:
            logger.warning("OIDC provider does not advertise end_session_endpoint.")
        return redirect_target

    async def userinfo(self, id_token: IDToken, header: Dict[str, Payload]) -> UserInfo:
        """Fetch user details using the userinfo endpoint.

        The method first tries to create :class:`~py_oidc_auth.schema.UserInfo`
        from the already decoded token.
        If required fields are missing it calls the provider ``userinfo``
        endpoint.

        :param id_token: Verified token obtained through :meth:`_get_token`.
        :param header: Request headers. The method uses ``Authorization``.
        :returns: Parsed user information.
        :raises InvalidRequest: If the provider request fails.

        Request example

        .. code-block:: text

            GET /auth/v2/userinfo HTTP/1.1
            Host: app.example.org
            Authorization: Bearer <access token>

        """
        token_data: Dict[str, Payload] = {
            k.lower(): str(v) for (k, v) in dict(id_token).items() if v is not None
        }
        authorization = cast(str, process_payload(header, "authorization"))
        return await query_user(token_data, authorization, self.config)

    # ------------------------------------------------------------------
    # Broker methods — framework-agnostic, called by all adapters
    # ------------------------------------------------------------------

    async def broker_jwks(self) -> Dict[str, Any]:
        """Return the broker public key as a JWKS document.

        Framework adapters expose this via a ``GET /.well-known/jwks.json``
        endpoint so external services can verify broker JWTs.

        :returns: JWKS document as a plain dict.
        :raises RuntimeError: If ``broker_mode`` is ``False``.

        Example
        -------
        .. code-block:: python

            # Flask
            @app.get("/auth/v2/.well-known/jwks.json")
            async def jwks():
                return jsonify(await auth.broker_jwks())

        """
        if not self.broker_mode:
            raise RuntimeError("broker_jwks() requires broker_mode=True.")
        broker = await self._ensure_broker_ready()
        return dict(broker.jwks())

    async def broker_token(
        self,
        token_endpoint: str,
        code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        refresh_token: Optional[str] = None,
        device_code: Optional[str] = None,
        code_verifier: Optional[str] = None,
        subject_token: Optional[str] = None,
        grant_type: Optional[str] = None,
    ) -> "Token":
        """Unified broker token endpoint — framework-agnostic entry point.

        Handles all grant types supported in broker mode:

        * **Auth code** — pass ``code`` + ``redirect_uri`` (+ optional
          ``code_verifier`` for PKCE).
        * **Device code** — pass ``device_code``.
        * **Broker refresh** — pass ``refresh_token`` (a previously issued
          broker JWT); extracts the ``jti``, looks up the stored IDP refresh
          token, rotates the session and returns a new broker JWT.
        * **RFC 8693 token exchange** — pass
          ``grant_type='urn:ietf:params:oauth:grant-type:token-exchange'``
          and ``subject_token=<IDP access token>``; validates the IDP token
          and issues a broker JWT directly.

        In all cases the response :class:`~py_oidc_auth.schema.Token` contains
        the broker JWT as both ``access_token`` and ``refresh_token``.

        :param token_endpoint: Full path used to compute default redirect URIs.
        :param code: Authorization code (auth-code flow).
        :param redirect_uri: Redirect URI for the auth-code exchange.
        :param refresh_token: Broker JWT to refresh.
        :param device_code: Device code for polling.
        :param code_verifier: PKCE verifier.
        :param subject_token: IDP access token for RFC 8693 exchange.
        :param grant_type: Grant type; pass the RFC 8693 URN for token exchange.
        :returns: :class:`~py_oidc_auth.schema.Token` with broker JWT.
        :raises InvalidRequest: On IDP errors, invalid tokens or missing args.

        Example (FastAPI adapter internal call)
        ----------------------------------------
        .. code-block:: python

            token = await auth.broker_token(
                token_endpoint="/api/auth/v2/token",
                device_code="DEV-123",
            )

        """
        from .broker.issuer import GRANT_TYPE_TOKEN_EXCHANGE

        _ = await self._ensure_broker_ready()

        if grant_type == GRANT_TYPE_TOKEN_EXCHANGE and subject_token:
            return await self.broker_exchange(subject_token)

        if refresh_token and not code and not device_code:
            return await self.broker_refresh(
                freva_jwt=refresh_token,
                token_endpoint=token_endpoint,
            )

        is_device = bool(device_code)
        expiry = 2592000 if is_device else 3600  # 30 days device, 1 hour code

        idp_token = await self.token(
            token_endpoint,
            code=code,
            redirect_uri=redirect_uri,
            device_code=device_code,
            code_verifier=code_verifier,
        )
        return await self.mint_and_store(idp_token, expiry_seconds=expiry)

    async def mint_and_store(
        self,
        idp_token: "Token",
        expiry_seconds: int = 3600,
    ) -> "Token":
        """Validate an IDP token, mint a broker JWT and persist the session.

        Called after any successful IDP exchange (auth-code, device-code).
        Validates the IDP access token claims, resolves the username, mints a
        broker JWT and stores the IDP refresh token for later rotation.

        :param idp_token: Raw IDP token from :meth:`token`.
        :param expiry_seconds: Broker JWT lifetime in seconds.
        :returns: :class:`~py_oidc_auth.schema.Token` carrying the broker JWT
            as both ``access_token`` and ``refresh_token``.
        :raises InvalidRequest: If IDP token validation fails.
        """
        import datetime as _dt

        broker = await self._ensure_broker_ready()

        idp_claims = await self._get_token(
            idp_token.access_token,
            effective_claims=self.config.claims,
        )
        header = {"authorization": f"Bearer {idp_token.access_token}"}
        try:
            user_info = await self.make_oidc_request(
                "GET",
                "userinfo_endpoint",
                headers=header,
            )
        except (InvalidRequest, KeyError) as error:
            logger.warning(
                "Could not set user_info: %s %s", error, idp_token.access_token
            )
            user_info = {}
        username = await get_username(
            current_user=idp_claims,
            cfg=self.config,
            header=header,
            user_info=user_info,
        )
        broker_jwt, jti = broker.mint(
            sub=username or idp_claims.sub or "",
            email=idp_claims.email,
            roles=idp_claims.flattened_roles,
            preferred_username=username,
            expiry_seconds=expiry_seconds,
        )
        await broker.save_session(
            jti=jti,
            sub=idp_claims.sub,
            refresh_token=idp_token.refresh_token,
            expires_at=idp_token.refresh_expires,
            user_info=json.dumps(user_info),
        )

        now = _dt.datetime.now(tz=_dt.timezone.utc)
        broker_expires = int((now + _dt.timedelta(seconds=expiry_seconds)).timestamp())
        return Token(
            access_token=broker_jwt,
            token_type="Bearer",
            expires=broker_expires,
            refresh_token=broker_jwt,
            refresh_expires=idp_token.refresh_expires,
            scope=idp_token.scope,
        )

    async def broker_refresh(
        self,
        freva_jwt: str,
        token_endpoint: str,
    ) -> "Token":
        """Refresh a broker session using the stored IDP refresh token.

        Accepts expired broker JWTs — only the ``jti`` claim is needed to
        look up the session.  The old session is deleted before the new one
        is created (rotation).

        :param freva_jwt: Current broker JWT (may be expired).
        :param token_endpoint: Token endpoint path for the IDP refresh call.
        :returns: Fresh :class:`~py_oidc_auth.schema.Token` with new broker JWT.
        :raises InvalidRequest: If the JWT is unparsable or the session is gone.
        """
        import jwt as _pyjwt

        broker = await self._ensure_broker_ready()

        # Accept expired tokens — we only need the jti
        try:
            id_token = broker.verify(freva_jwt)
            jti: Optional[str] = (
                str(
                    getattr(id_token, "jti", None)
                    or (id_token.model_extra or {}).get("jti")
                    or ""
                )
                or None
            )
        except _pyjwt.ExpiredSignatureError:
            unverified: Dict[str, Any] = _pyjwt.decode(
                freva_jwt,
                options={"verify_signature": False, "verify_exp": False},
            )
            raw_jti = unverified.get("jti")
            jti = str(raw_jti) if raw_jti else None
        except _pyjwt.PyJWTError as exc:
            raise InvalidRequest(401, detail=f"Invalid refresh token: {exc}")

        if not jti:
            raise InvalidRequest(401, detail="Invalid refresh token: missing jti.")

        session = await broker.get_session(jti)
        if not session:
            raise InvalidRequest(
                401,
                detail="Session expired or not found. Please re-authenticate.",
            )
        _, idp_refresh_token = session

        # Rotate: remove old session before issuing a new one
        await broker.delete_session(jti)

        idp_token = await self.token(token_endpoint, refresh_token=idp_refresh_token)
        return await self.mint_and_store(idp_token)

    async def broker_exchange(self, subject_token: str) -> "Token":
        """RFC 8693 token exchange: validate an IDP access token, mint broker JWT.

        The ``subject_token`` must be a valid IDP access token.  It is
        verified against the IDP JWKS.  On success a broker JWT is issued.

        Because a plain token exchange does not yield an IDP refresh token, the
        resulting broker session cannot be silently refreshed via
        :meth:`broker_refresh`.  Clients that need long-lived sessions should
        use the device-code or auth-code flow instead.

        :param subject_token: IDP access token to exchange.
        :returns: :class:`~py_oidc_auth.schema.Token` with broker JWT.
        :raises InvalidRequest: If the IDP token is invalid.
        """
        import datetime as _dt

        broker = await self._ensure_broker_ready()

        idp_claims = await self._get_token(
            subject_token,
            effective_claims=self.config.claims,
        )

        username = await get_username(
            current_user=idp_claims,
            header={"authorization": f"Bearer {subject_token}"},
            cfg=self.config,
        )

        broker_jwt, jti = broker.mint(
            sub=username or idp_claims.sub or "",
            email=idp_claims.email,
            roles=idp_claims.flattened_roles,
            preferred_username=username,
        )

        now = _dt.datetime.now(tz=_dt.timezone.utc)
        short_ttl = int((now + _dt.timedelta(hours=1)).timestamp())

        # No IDP refresh token available from a plain exchange
        await broker.save_session(
            jti=jti,
            sub=idp_claims.sub,
            refresh_token="",
            expires_at=idp_claims.exp or short_ttl,
        )

        expires = int((now + _dt.timedelta(seconds=3600)).timestamp())
        return Token(
            access_token=broker_jwt,
            token_type="Bearer",
            expires=expires,
            refresh_token=broker_jwt,
            refresh_expires=expires,
            scope="openid profile email",
        )
