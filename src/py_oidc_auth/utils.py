"""Utility helpers and configuration.

This module contains:

* :class:`OIDCConfig`, a dataclass that holds all OpenID Connect settings
* HTTP helper functions used by :class:`~py_oidc_auth.auth_base.OIDCAuth`
* Claim and header helpers used by the framework adapters

The functions in this module are part of the public surface of the package.
They are small, stable building blocks that you can use if you build your own
adapter.

"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, cast

import httpx
import jwt
from pydantic import ValidationError
from typing_extensions import NotRequired, TypedDict

from .exceptions import InvalidRequest
from .schema import IDToken, Payload, UserInfo

logger = logging.getLogger(__name__)


def process_payload(payload: Dict[str, Payload], key: str) -> Payload:
    """Look up a header or payload value with flexible key casing.

    The function checks several common casing variants of *key* and returns
    the first match.

    :param payload: Mapping to search in.
    :param key: Key to look up.
    :returns: The matching value or ``None``.

    Example
    -------
    .. code-block:: python

        authorization = process_payload(dict(request.headers), "authorization")

    """
    for k in (key, key.lower(), key[0].upper() + key[1:], key.upper()):
        if k in payload:
            return payload[k]
    return None


@dataclass
class OIDCConfig:
    """Configuration required to talk to an OpenID Connect provider.

    :param client_id: OIDC client identifier.
    :param discovery_url: Full URL to the discovery document.
    :param client_secret: Client secret for confidential clients.
    :param scopes: Default scopes.
    :param proxy: Public base URL of your application.
    :param claims: Optional claim constraints.
    :param offline_access: If true, include ``offline_access`` in scope.
    :param timeout: HTTP timeout for outbound requests.
    :param verify_exp: Whether to verify the expiry claim. Default ``True``.
    :param verify_iss: Whether to verify the issuer claim. Default ``True``.
    :param verify_aud: Whether to verify the audience claim. Default ``True``.
    :param verify_nbf: Whether to verify the not-before claim. Default ``True``.

    The discovery document is fetched lazily when
    :attr:`oidc_overview` is accessed.

    Example
    -------
    .. code-block:: python

        cfg = OIDCConfig(
            client_id="my client",
            discovery_url="https://idp.example.org/.well-known/openid-configuration",
            scopes=["openid", "profile"],
        )
        token_endpoint = cfg.oidc_overview["token_endpoint"]

    """

    client_id: str
    discovery_url: str = ""
    client_secret: Optional[str] = None
    scopes: Optional[List[str]] = None
    proxy: str = ""
    claims: Optional[Dict[str, Any]] = None
    offline_access: bool = True
    timeout: Optional[httpx.Timeout] = None
    verify_exp: bool = True
    verify_iss: bool = True
    verify_aud: bool = True
    verify_nbf: bool = True

    def __post_init__(self) -> None:
        """Post init."""
        self._oidc_overview: Optional[Dict[str, Payload]] = None
        self.timeout = self.timeout or httpx.Timeout(10)
        self.scopes = list(self.scopes or [])

    @property
    def oidc_overview(self) -> Dict[str, Payload]:
        """The provider discovery document.

        If the discovery document has not been loaded yet, it is fetched from
        :attr:`discovery_url`.

        :returns: Discovery document as a dict. Returns an empty dict on failure.

        Notes
        -----
        The HTTP client uses ``verify=False`` and follows redirects.
        If you require strict TLS verification, wrap this class or adjust the
        implementation.

        """
        if self._oidc_overview:
            return self._oidc_overview

        try:
            with httpx.Client(
                timeout=self.timeout, verify=True, follow_redirects=True
            ) as session:
                resp = session.get(self.discovery_url)
                resp.raise_for_status()
                if resp.status_code == 200:
                    self._oidc_overview = resp.json()
        except Exception as exc:
            logger.exception("Failed to fetch OIDC discovery: %s", exc)
        return self._oidc_overview or {}


class SystemUserInfo(TypedDict):
    """User information extracted from token or userinfo response."""

    email: NotRequired[str]
    last_name: NotRequired[str]
    first_name: NotRequired[str]
    username: NotRequired[str]
    pw_name: NotRequired[str]


class CacheTokenPayload(TypedDict):
    """Payload format used by cache tokens."""

    path: List[str]
    exp: float
    assembly: Optional[Dict[str, Optional[str]]]


def string_to_dict(string: str) -> Dict[str, List[str]]:
    """Parse a simple ``key:value`` list into a dict.

    The input is a comma separated list.
    Duplicate keys are collected into a list and duplicates are removed.

    :param string: For example ``"key1:value1,key2:value2,key1:value2"``.
    :returns: A mapping like ``{"key1": ["value1", "value2"], "key2": ["value2"]}``.

    Example
    -------
    .. code-block:: python

        assert string_to_dict("a:1,a:2,b:2") == {"a": ["1", "2"], "b": ["2"]}

    """
    result: Dict[str, List[str]] = {}
    for kv in string.split(","):
        key, _, value = kv.partition(":")
        if key and value:
            result.setdefault(key, [])
            if value not in result[key]:
                result[key].append(value)
    return result


def token_field_matches(
    token: str, claims: Optional[Dict[str, Any]] = None
) -> bool:
    """Check claim constraints against an encoded JWT.

    The function decodes the JWT without verifying the signature and checks
    that a set of claim constraints matches.

    The *claims* argument maps a claim path to a list of acceptable values.
    Nested claims can be expressed using dot notation.

    :param token: Encoded JWT.
    :param claims: Mapping from claim path to acceptable values.
    :returns: True if all constraints match.

    Example
    -------
    .. code-block:: python

        ok = token_field_matches(
            token,
            claims={
                "groups": ["admins"],
                "realm_access.roles": ["offline_access"],
            },
        )

    """

    def _walk_dict(inp: Any, keys: List[str]) -> Any:
        if not keys or not isinstance(inp, dict) or not inp:
            return inp or ""
        return _walk_dict(inp.get(keys[0]), keys[1:])

    matches: List[bool] = []
    token_data: Dict[str, Any] = {}
    for claim, pattern in (claims or {}).items():
        if not token_data:
            token_data = jwt.decode(token, options={"verify_signature": False})
        value_str = str(_walk_dict(token_data, claim.split(".")))
        for p in pattern:
            matches.append(
                bool(re.search(rf"\b{re.escape(str(p))}\b", value_str))
            )
    return all(matches)


def get_userinfo(user_info: Dict[str, str]) -> SystemUserInfo:
    """Map provider specific user fields into a normalised structure.

    Providers use different claim names for the same concept.
    This helper applies a best effort mapping.

    :param user_info: Mapping created from token claims or a userinfo response.
    :returns: A normalised mapping.

    Example
    -------
    .. code-block:: python

        mapped = get_userinfo({"preferred_username": "janedoe", "mail": "a@b"})

    """
    output: Dict[str, str] = {}
    keys = {
        "email": ("mail", "email"),
        "username": ("preferred-username", "user-name", "uid"),
        "last_name": ("last-name", "family-name", "name", "surname"),
        "first_name": ("first-name", "given-name"),
    }
    for key, entries in keys.items():
        for entry in entries:
            if user_info.get(entry):
                output[key] = user_info[entry]
                break
            if user_info.get(entry.replace("-", "_")):
                output[key] = user_info[entry.replace("-", "_")]
                break

    name = output.get("first_name", "") + " " + output.get("last_name", "")
    return SystemUserInfo(
        first_name=name.partition(" ")[0],
        last_name=name.rpartition(" ")[-1],
        email=output.get("email", ""),
        username=output.get("username", ""),
        pw_name=output.get("username", ""),
    )


async def oidc_request(
    url: str,
    method: str,
    *,
    data: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[httpx.Timeout] = None,
) -> Dict[str, Any]:
    """Make an HTTP request to an OpenID Connect provider.

    :param url: Target URL.
    :param method: HTTP method.
    :param data: Optional form data.
    :param headers: Optional request headers.
    :param timeout: Optional httpx timeout.
    :returns: Response JSON.
    :raises InvalidRequest: If the provider responds with an error or the
        request fails.

    Example
    -------
    .. code-block:: python

        data = {"grant_type": "refresh_token", "refresh_token": "..."}
        result = await oidc_request(token_endpoint, "POST", data=data)

    """
    timeout = timeout or httpx.Timeout(10)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=True, follow_redirects=True
        ) as session:
            resp = await session.request(method, url, data=data, headers=headers)
            if resp.status_code >= 400:
                raise InvalidRequest(
                    status_code=resp.status_code,
                    detail=f"Upstream OIDC error: {resp.text}",
                )
            result: Dict[str, Any] = resp.json()
            return result
    except InvalidRequest:
        raise
    except Exception as exc:
        raise InvalidRequest(
            status_code=502,
            detail=f"Failed to contact OIDC endpoint: {exc}",
        )


async def query_user(
    token_data: Dict[str, str], authorization: str, cfg: OIDCConfig
) -> UserInfo:
    """Create :class:`UserInfo` from token claims or the userinfo endpoint.

    The function first attempts to build :class:`~py_oidc_auth.schema.UserInfo`
    from token claims.
    If required fields are missing, it calls the provider userinfo endpoint.

    :param token_data: Token claims in a lower cased mapping.
    :param authorization: Value of the Authorization header.
    :param cfg: OIDC configuration.
    :returns: Parsed user information.
    :raises InvalidRequest: If user information cannot be obtained.

    """
    try:
        return UserInfo(**get_userinfo(token_data))
    except ValidationError:
        token_data = cast(
            Dict[str, str],
            await oidc_request(
                cast(str, cfg.oidc_overview["userinfo_endpoint"]),
                "GET",
                headers={"Authorization": authorization},
            ),
        )
        try:
            return UserInfo(
                **get_userinfo(
                    {k.lower(): str(v) for (k, v) in token_data.items()}
                )
            )
        except ValidationError:
            raise InvalidRequest(status_code=404)


async def get_username(
    current_user: Optional[IDToken],
    header: Dict[str, Any],
    cfg: OIDCConfig,
) -> Optional[str]:
    """Return a usable username.

    The function prefers explicit username fields in the token.
    If they are missing it tries the userinfo endpoint.
    As a last resort it returns the ``sub`` claim.

    :param current_user: Verified token.
    :param header: Request headers.
    :param cfg: OIDC configuration.
    :returns: Username or ``None``.

    Example
    -------
    .. code-block:: python

        username = await get_username(token, dict(request.headers), auth.config)

    """
    if not current_user:
        return None

    def _extract_username(
        obj: Any,
        fields: List[str] = ["preferred_username", "username", "user_name"],
    ) -> Optional[str]:
        for field in fields:
            value = getattr(obj, field, None)
            if value:
                return cast(Optional[str], value)
        return None

    username = _extract_username(current_user)
    if username:
        return username

    authorization = header.get("authorization")
    if authorization:
        token_data = {k.lower(): str(v) for (k, v) in dict(current_user).items()}
        try:
            user_data = await query_user(token_data, authorization, cfg)
            username = _extract_username(user_data)
            if username:
                return username
        except InvalidRequest:
            pass

    return getattr(current_user, "sub", None)
