"""Reusable OpenID Connect authentication library.

The package provides a framework independent core and optional adapters for
popular Python web frameworks.

Framework adapters are imported lazily so that installing one extra does not
pull in the dependencies for every framework.

Install via pip

.. code-block:: text

    pip install py-oidc-auth[fastapi]
    pip install py-oidc-auth[flask]
    pip install py-oidc-auth[quart]
    pip install py-oidc-auth[tornado]
    pip install py-oidc-auth[litestar]
    pip install py-oidc-auth[django]

Install via conda/mamba/micromamba


.. code-block:: text

    conda install py-oidc-auth-fastapi
    conda install py-oidc-auth-flast
    conda install py-oidc-auth-quart
    conda install py-oidc-auth-tornado
    conda install py-oidc-auth-litestar
    conda install py-oidc-auth-django

``py-oidc-auth`` can either pass through access tokens issued the Identity Provider
(IdP) or mint own tokens. For token minting set `broker_mode=True`. In broker
mode the IdP token will be stored server side on either a mongoDB, postgresDB,
mySQL, mariaDB or a sqLite. By setting trusted issuers you can define a network
of issues for token trust and implements a token federation where different
applications trust each others tokens.

Example with FastAPI:

.. code-block:: python

    from py_oidc_auth import FastApiOIDCAuth

    auth = FastApiOIDCAuth(
        client_id="myapp",
        discovery_url="https://idp.example.org/.well-known/openid-configuration",
        broker_mode=True,
        broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
        broker_audience="myapp-api",
        trusted_issuers=["https://other-instance.example.org"],
    )
    app.include_router(auth.create_auth_router(prefix="/api"))


Example with Flask using a pre token storage objects:

.. code-block:: python

    from py_oidc_auth import FlaskOIDCAuth, MongoDBBrokerStore
    from pymongo import AsyncMongoClient
    mongo_client = AsyncMongoClient("mongodb://myser:mypass@host")
    auth =  FlaskOIDCAuth(
                client_id="myapp",
                discovery_url="https://idp.example.org/.well-known/openid-configuration",
                broker_mode=True,
                broker_store_obj=MongoDBBrokerStore(db=mongo_client["my-app"]),
                broker_audience="myapp-api",
                trusted_issuers=["https://other-instance.example.org"],
           )
    app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

Public API
----------
"""

from typing import TYPE_CHECKING, Any

from .auth_base import OIDCAuth
from .broker.issuer import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    TokenBroker,
)
from .broker.store import (
    BrokerStore,
    InMemoryBrokerStore,
    JWKSDict,
    MongoDBBrokerStore,
    SQLAlchemyBrokerStore,
    create_broker_store,
)
from .schema import IDToken, Token
from .utils import string_to_dict

if TYPE_CHECKING:
    from .django_auth import DjangoOIDCAuth
    from .fastapi_auth import FastApiOIDCAuth
    from .flask_auth import FlaskOIDCAuth
    from .litestar_auth import LitestarOIDCAuth
    from .quart_auth import QuartOIDCAuth
    from .tornado_auth import TornadoOIDCAuth

__version__ = "2604.2.1"

_LAZY_IMPORTS = {
    "FastApiOIDCAuth": ".fastapi_auth",
    "FlaskOIDCAuth": ".flask_auth",
    "QuartOIDCAuth": ".quart_auth",
    "TornadoOIDCAuth": ".tornado_auth",
    "LitestarOIDCAuth": ".litestar_auth",
    "DjangoOIDCAuth": ".django_auth",
}


def __getattr__(name: str) -> Any:
    """Lazy import framework adapters.

    This keeps import time low and avoids importing optional dependencies
    unless they are requested.

    :param name: Attribute requested from the package.
    :returns: Imported attribute.
    :raises AttributeError: If the attribute does not exist.

    """
    if name in _LAZY_IMPORTS:
        import importlib

        module = importlib.import_module(_LAZY_IMPORTS[name], __name__)
        return getattr(module, name)
    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )  # pragma: no cover


__all__ = [
    "BrokerStore",
    "DjangoOIDCAuth",
    "FastApiOIDCAuth",
    "FlaskOIDCAuth",
    "IDToken",
    "InMemoryBrokerStore",
    "JWKSDict",
    "LitestarOIDCAuth",
    "MongoDBBrokerStore",
    "OIDCAuth",
    "QuartOIDCAuth",
    "SQLAlchemyBrokerStore",
    "TornadoOIDCAuth",
    "Token",
    "TokenBroker",
    "create_broker_store",
    "string_to_dict",
    "__version__",
    "GRANT_TYPE_TOKEN_EXCHANGE",
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_REFRESH",
]
