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
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union, cast

import httpx
from pydantic import ValidationError
from typing_extensions import NotRequired, TypedDict

from .exceptions import InvalidRequest
from .schema import FlatPayload, IDToken, Payload, UserInfo

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
    audience: Optional[str] = None
    proxy: str = ""
    claims: Optional[Dict[str, Any]] = None
    offline_access: bool = True
    timeout: Optional[httpx.Timeout] = None

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


def extract_claims(
    data: Mapping[str, Payload],
    keys: List[str],
) -> Dict[str, FlatPayload]:
    """Extract specific claims from a nested dictionary.

    Recursively traverses nested dicts searching for the given keys.
    Returns as soon as all requested keys are found. If a key appears
    at multiple levels of nesting, the first occurrence (shallowest /
    earliest in iteration order) wins.

    Parameters
    ----------
    data:
        The nested dictionary to search, typically a token or userinfo
        payload from an IDP.
    keys:
        The claim names to extract.

    Returns
    -------
    Dict[str, FlatPayload]
        A flat dictionary containing the found claims. May be incomplete
        if not all keys were present in the data.

    """
    remaining = set(keys)
    result: Dict[str, FlatPayload] = {}

    def _search(obj: Mapping[str, Payload]) -> None:
        if not remaining or not isinstance(obj, dict):  # pragma: no cover
            return
        for key, value in obj.items():
            if not remaining:
                return
            if isinstance(value, dict):
                _search(value)
            elif key in remaining:
                result[key] = value
                remaining.discard(key)

    for key, value in data.items():
        if not remaining:
            break
        if isinstance(value, dict):
            _search(value)
        elif key in remaining:
            result[key] = value
            remaining.discard(key)

    return result


def token_field_matches(
    token: str,
    claims: Optional[Union[str, Iterable[str], Dict[str, Iterable[str]]]] = None,
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
            claims=["admins", "offline_access"]
        )

    """
    claims = [claims] if (isinstance(claims, str) and claims) else claims or []
    claims_list: List[str] = []
    for c in claims.values() if isinstance(claims, dict) else map(str, claims):
        claims_list += [c] if isinstance(c, str) else list(map(str, c))
    roles = IDToken.from_token(token).flattened_roles
    return all(c in roles for c in claims_list)


def get_userinfo(user_info: Dict[str, Payload]) -> SystemUserInfo:
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
        "email": ["mail", "email"],
        "username": ["preferred-username", "user-name", "uid", "username"],
        "last_name": ["last-name", "family-name", "name", "surname"],
        "first_name": ["first-name", "given-name"],
    }
    claims = []
    for attrs in keys.values():
        for attr in attrs:
            claims.append(attr)
            claims.append(attr.replace("-", "_"))
    claims = list(set(claims))
    flat_user_info = cast(Dict[str, str], extract_claims(user_info, list(set(claims))))
    for key, entries in keys.items():
        for entry in entries:
            v1 = flat_user_info.get(entry)
            v2 = flat_user_info.get(entry.replace("-", "_"))
            v = v1 or v2
            if v:
                output[key] = v
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
    token_data: Dict[str, Payload], authorization: str, cfg: OIDCConfig
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
            Dict[str, Payload],
            await oidc_request(
                cast(str, cfg.oidc_overview["userinfo_endpoint"]),
                "GET",
                headers={"Authorization": authorization},
            ),
        )
        try:
            return UserInfo(
                **get_userinfo({k.lower(): str(v) for (k, v) in token_data.items()})
            )
        except ValidationError:
            raise InvalidRequest(status_code=404)


async def get_username(
    current_user: Optional[IDToken],
    header: Dict[str, Any],
    cfg: OIDCConfig,
    user_info: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Return a usable username.

    The function prefers explicit username fields in the token.
    If they are missing it tries the userinfo endpoint.
    As a last resort it returns the ``sub`` claim.

    :param current_user: Verified token.
    :param header: Request headers.
    :param cfg: OIDC configuration.
    :param user_info: Optional user information from a previous userinfo query.
    :returns: Username or ``None``.

    Example
    -------
    .. code-block:: python

        username = await get_username(token, dict(request.headers), auth.config)

    """
    if not current_user:
        return None

    token_data: Dict[str, Payload] = {
        k.lower(): v for (k, v) in current_user.model_dump().items()
    }
    username = get_userinfo(user_info or token_data).get("username")
    if username:
        return username

    authorization = header.get("authorization")
    if authorization:
        try:
            user_data = await query_user(token_data, authorization, cfg)
            username = get_userinfo(user_data.model_dump()).get("username")
            if username:
                return username
        except InvalidRequest:
            pass

    return getattr(current_user, "sub", None)
