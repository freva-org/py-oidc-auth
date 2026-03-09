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

Example with FastAPI

.. code-block:: python

    from py_oidc_auth import FastApiOIDCAuth

    auth = FastApiOIDCAuth(...)
    app.include_router(auth.create_auth_router(prefix="/api"))

Example with Flask

.. code-block:: python

    from py_oidc_auth import FlaskOIDCAuth

    auth = FlaskOIDCAuth(...)
    app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

"""

from typing import TYPE_CHECKING, Any

from .auth_base import OIDCAuth
from .schema import IDToken
from .utils import string_to_dict

if TYPE_CHECKING:
    from .django_auth import DjangoOIDCAuth
    from .fastapi_auth import FastApiOIDCAuth
    from .flask_auth import FlaskOIDCAuth
    from .litestar_auth import LitestarOIDCAuth
    from .quart_auth import QuartOIDCAuth
    from .tornado_auth import TornadoOIDCAuth

__version__ = "2603.0.1"

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
    "DjangoOIDCAuth",
    "FastApiOIDCAuth",
    "FlaskOIDCAuth",
    "IDToken",
    "LitestarOIDCAuth",
    "OIDCAuth",
    "QuartOIDCAuth",
    "TornadoOIDCAuth",
    "string_to_dict",
    "__version__",
]
