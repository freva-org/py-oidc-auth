"""Pydantic models and types used by py oidc auth.

The framework adapters return these models from the built in authentication
endpoints.
They are also used as types for dependency injection and decorators.

All models are compatible with OpenAPI generation in supported frameworks.

"""

from typing import Annotated, Any, Dict, List, Literal, Optional, Union

import jwt as pyjwt
from pydantic import BaseModel, ConfigDict, Field

PayloadContent = Optional[Union[str, int, float, bool]]
Payload = Optional[
    Union[Dict[str, "PayloadContent"], List["PayloadContent"], "PayloadContent"]
]
FlatPayload = Union[PayloadContent, List[PayloadContent]]

PromptField = Literal["none", "login", "consent", "select_account"]


class IDToken(BaseModel):
    """Decoded OpenID Connect token.

    Standard claims are optional to allow interoperability across providers.
    Additional provider specific claims are preserved.

    Example
    -------
    .. code-block:: python

        token = IDToken(**payload)
        print(token.sub)
        print(token.get("groups"))

    """

    model_config = ConfigDict(extra="allow")

    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[Union[str, List[str]]] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    nonce: Optional[str] = None
    azp: Optional[str] = None
    scope: Optional[str] = None

    preferred_username: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    groups: Optional[List[str]] = None
    realm_access: Optional[Dict[str, Any]] = None
    resource_access: Optional[Dict[str, Any]] = None
    roles: Optional[List[str]] = None

    @property
    def flattened_roles(self) -> List[str]:
        """Flat list of roles from any standard location."""
        # Roles from Keycloak realm_access
        realm_roles = (self.realm_access or {}).get("roles") or []
        # Groups from Keycloak
        resource_roles = [
            r
            for c in (self.resource_access or {}).values()
            for r in c.get("roles") or []
        ]
        groups = self.groups or []
        roles = self.roles or []

        return list({*realm_roles, *groups, *roles, *resource_roles})

    @classmethod
    def from_token(
        cls,
        token: str,
        algorithms: Optional[List[str]] = None,
    ) -> "IDToken":
        """Create an IDToken from an encoded JWT.

        Decodes without signature verification when no key is provided.

        :param token: Encoded JWT string.
        :param key: Public key or secret for signature verification.
        :param algorithms: Accepted algorithms, e.g. ``["RS256"]``.
        :param audience: Expected ``aud`` claim.
        :param issuer: Expected ``iss`` claim.
        :returns: Populated IDToken instance.

        Example
        -------
        .. code-block:: python

            # No verification
            token = IDToken.from_token(encoded)

            # With full verification
            token = IDToken.from_token(
                encoded,
                key=public_key,
                algorithms=["RS256"],
                audience="freva-api",
            )
        """
        return cls(
            **pyjwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=algorithms or ["RS256"],
            )
        )


class Token(BaseModel):
    """Token response returned by the token endpoint.

    This model normalises common fields across providers.

    Example
    -------
    .. code-block:: python

        token = Token(
            access_token="...",
            token_type="Bearer",
            expires=1710000000,
            refresh_token="...",
            refresh_expires=1710003600,
            scope="openid profile",
        )

    """

    access_token: str
    token_type: str
    expires: int
    refresh_token: str
    refresh_expires: int
    scope: str


class DeviceStartResponse(BaseModel):
    """Response returned when starting the device authorization flow.

    The user should open ``verification_uri`` and enter ``user_code``.

    Example
    -------
    .. code-block:: python

        start = await auth.device_flow()
        print(start.verification_uri)
        print(start.user_code)

    """

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: Optional[str] = None
    expires_in: int
    interval: int = 5


class TokenisedUser(BaseModel):
    """A minimal user identifier.

    This model is useful in places where only a single stable identifier
    is required.

    """

    pw_name: Annotated[
        str,
        Field(
            description="Username or user id.",
            examples=["janedoe"],
        ),
    ]


class UserInfo(BaseModel):
    """Normalised user profile.

    Providers use different claim names for user information.
    The library attempts to map common claim names into this structure.

    Example
    -------
    .. code-block:: python

        info = await auth.userinfo(token, headers)
        print(info.email)

    """

    username: Annotated[
        str,
        Field(
            title="User name",
            description="Username or uid of the user the token belongs to.",
            min_length=1,
            examples=["janedoe"],
        ),
    ]
    last_name: Annotated[
        str,
        Field(
            title="Last name",
            description="Surname of the user the token belongs to.",
        ),
    ]
    first_name: Annotated[
        str,
        Field(
            title="First name",
            description="Given name of the user the token belongs to.",
        ),
    ]
    pw_name: Annotated[str, Field(description="Alias of username")]
    email: Annotated[
        Optional[str],
        Field(
            default=None,
            title="Email",
            description="Email address of the user the token belongs to.",
        ),
    ] = None
