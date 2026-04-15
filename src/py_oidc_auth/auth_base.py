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
import logging
import secrets
from typing import Any, Dict, Optional, Set, Union, cast
from urllib.parse import urlencode, urljoin

import httpx
import jwt as pyjwt

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

    Example
    -------
    .. code-block:: python

        auth = OIDCAuth(
            client_id="my client",
            discovery_url="https://idp.example.org/.well-known/openid-configuration",
            client_secret="secret",
            scopes="myscope profile email",
            audience="my-aud",
        )

    """

    _lock = asyncio.Lock()

    def __init__(
        self,
        client_id: str = "",
        discovery_url: str = "",
        client_secret: Optional[str] = None,
        scopes: str = "profile email",
        audience: Optional[str] = None,
        proxy: str = "",
        claims: Optional[Dict[str, Any]] = None,
        offline_access: bool = True,
        timeout_sec: int = 10,
    ) -> None:
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
        self._verifier: Optional[TokenVerifier] = None

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
                self._verifier = TokenVerifier(
                    jwks_uri=cast(str, self.config.oidc_overview["jwks_uri"]),
                    issuer=cast(Optional[str], self.config.oidc_overview.get("issuer")),
                    audience=self.config.audience,
                    timeout=self.config.timeout,
                )
                logger.info("OIDC initialized from %s", self.config.discovery_url)
            except Exception as exc:
                logger.exception("Failed to initialise OIDC: %s", exc)

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
            _state_token, redirect_uri, code_verifier = state.split("|", 2)
        except ValueError:
            raise InvalidRequest(400, detail="Invalid state format")

        data: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        headers: Dict[str, str] = {}
        _set_request_header(
            self.config.client_id, self.config.client_secret, data, headers
        )
        return await self.make_oidc_request(
            "POST",
            "token_endpoint",
            data={k: v for k, v in data.items() if v},
            headers=headers,
        )

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
        token_data = {
            k.lower(): str(v) for (k, v) in dict(id_token).items() if v is not None
        }
        authorization = cast(str, process_payload(header, "authorization"))
        return await query_user(token_data, authorization, self.config)
