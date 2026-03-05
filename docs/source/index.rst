.. image:: _static/logo.png
   :alt: py-oidc-auth logo
   :width: 560px
   :align: center

.. centered:: *A small, typed OpenID Connect helper for authentication and authorization.*

.. image:: https://img.shields.io/badge/License-BSD-purple.svg
   :target: LICENSE

.. image:: https://readthedocs.org/projects/py-oidc-auth/badge/?version=latest
   :target: https://py-oidc-auth.readthedocs.io/en/latest/?badge=latest

.. image:: https://codecov.io/gh/freva-org/py-oidc-auth/graph/badge.svg?token=9JP9UWixaf
   :target: https://codecov.io/gh/freva-org/py-oidc-auth

.. image:: https://img.shields.io/pypi/v/py-oidc-auth
   :target: https://pypi.org/project/py-oidc-auth/
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/py-oidc-auth
   :target: https://pypi.org/project/py-oidc-auth/
   :alt: Supported Python versions



It provides

* a framework independent async core: ``OIDCAuth``
* framework adapters that expose common auth endpoints
* simple ``required()`` and ``optional()`` helpers to protect routes


Supported frameworks
~~~~~~~~~~~~~~~~~~~~

.. grid:: 3
   :gutter: 2

   .. grid-item::

      .. figure:: _static/fastapi-logo.png
         :alt: FastAPI
         :height: 48px
         :align: center

         FastAPI

   .. grid-item::

      .. figure:: _static/flask-logo.svg
         :alt: Flask
         :height: 48px
         :align: center

         Flask

   .. grid-item::

      .. figure:: _static/quart-logo.png
         :alt: Quart
         :height: 48px
         :align: center

         Quart

   .. grid-item::

      .. figure:: _static/tornado-logo.png
         :alt: Tornado
         :height: 48px
         :align: center

         Tornado

   .. grid-item::

      .. figure:: _static/litestar-logo.svg
         :alt: Litestar
         :height: 48px
         :align: center

         Litestar

   .. grid-item::

      .. figure:: _static/django-logo.svg
         :alt: Django
         :height: 48px
         :align: center

         Django

Features
~~~~~~~~

* Authorization code flow with PKCE (login and callback)
* Refresh token flow
* Device authorization flow
* Userinfo lookup
* Provider initiated logout (end session) when supported
* Bearer token validation using provider JWKS, issuer, and audience
* Optional scope checks and simple claim constraints
* Full type annotations

Install
~~~~~~~

Pick your framework for installation with pip:

.. code-block:: console

   python -m pip install py-oidc-auth[fastapi]
   python -m pip install py-oidc-auth[flask]
   python -m pip install py-oidc-auth[quart]
   python -m pip install py-oidc-auth[tornado]
   python -m pip install py-oidc-auth[litestar]
   python -m pip install py-oidc-auth[django]

Or with conda/mamba/micromamba:

.. code-block:: console

   conda install -c conda-forge py-oidc-auth-fastapi
   conda install -c conda-forge py-oidc-auth-flask
   conda install -c conda-forge py-oidc-auth-quart
   conda install -c conda-forge py-oidc-auth-tornado
   conda install -c conda-forge py-oidc-auth-litestart
   conda install -c conda-forge py-oidc-auth-django


Import name is ``py_oidc_auth``:

.. code-block:: python

   from py_oidc_auth import OIDCAuth

Concepts
~~~~~~~~

Core
^^^^

``OIDCAuth`` is the framework independent client. It loads provider metadata from the
OpenID Connect discovery document, performs provider calls, and validates tokens.

Adapters
^^^^^^^^

Each adapter subclasses ``OIDCAuth`` and adds:

* helpers to register the standard endpoints (router, blueprint, urlpatterns, etc.)
* ``required()`` and ``optional()`` helpers to validate bearer tokens on protected routes

Default endpoints
~~~~~~~~~~~~~~~~~

Adapters can expose these paths (customizable and individually disableable):

* ``GET  /auth/v2/login``
* ``GET  /auth/v2/callback``
* ``POST /auth/v2/token``
* ``POST /auth/v2/device``
* ``GET  /auth/v2/logout``
* ``GET  /auth/v2/userinfo``

Quick start
~~~~~~~~~~~

Create one auth instance at app startup:

.. code-block:: python

   auth = ...(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
   )

.. tab-set::

    .. tab-item:: FastAPI

        .. code-block:: python

           from typing import Dict, Optional

           from fastapi import FastAPI
           from py_oidc_auth import FastApiOIDCAuth
           from py_oidc_auth.schema import IDToken

           app = FastAPI()

           auth = FastApiOIDCAuth(
               client_id="my client",
               client_secret="secret",
               discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
               scopes="myscope profile email",
           )

           app.include_router(auth.create_auth_router(prefix="/api"))

           @app.get("/me")
           async def me(token: IDToken = auth.required()) -> Dict[str, str]:
               return {"sub": token.sub}

           @app.get("/feed")
           async def feed(token: Optional[IDToken] = auth.optional()) -> Dict[str, str]:
               return {"authenticated": token is not None}


    .. tab-item:: Flask

        .. code-block:: python

           from flask import Flask, Response, jsonify
           from py_oidc_auth import FlaskOIDCAuth, IDToken

           app = Flask(__name__)

           auth = FlaskOIDCAuth(
               client_id="my client",
               client_secret="secret",
               discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
               scopes="myscope profile email",
           )

           app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

           @app.get("/protected")
           @auth.required()
           def protected(token: IDToken) -> Response:
               return jsonify({"sub": token.sub})

    .. tab-item:: Quart

        .. code-block:: python

           from quart import Quart, Response, jsonify
           from py_oidc_auth import QuartOIDCAuth IDToken

           app = Quart(__name__)

           auth = QuartOIDCAuth(
               client_id="my client",
               client_secret="secret",
               discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
               scopes="myscope profile email",
           )

           app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

           @app.get("/protected")
           @auth.required()
           async def protected(token: IDToken) -> Response:
               return jsonify({"sub": token.sub})

    .. tab-item:: Django

        Decorator style:

        .. code-block:: python

           from django.http import HttpRequest, JsonResponse
           from django.urls import path
           from py_oidc_auth import DjangoOIDCAuth, IDToken

           auth = DjangoOIDCAuth(
               client_id="my client",
               client_secret="secret",
               discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
               scopes="myscope profile email",
           )

           @auth.required()
           async def protected_view(request: HttpRequest, token: IDToken) -> JsonResponse:
               return JsonResponse({"sub": token.sub})

           urlpatterns = [
               \*auth.get_urlpatterns(prefix="api"),
               path("protected/", protected_view),
           ]

        Routes only:

        .. code-block:: python

           urlpatterns = [
               \*auth.get_urlpatterns(prefix="api"),
           ]

    .. tab-item:: Tornado

        .. code-block:: python

           import json
           import tornado.web
           from py_oidc_auth import TornadoOIDCAuth, IDToken

           auth = TornadoOIDCAuth(
                client_id="my client",
                client_secret="secret",
                discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
                scopes="myscope profile email",
           )

           class ProtectedHandler(tornado.web.RequestHandler):
               @auth.required()
               async def get(self, token: IDToken) -> None:
                   self.write(json.dumps({"sub": token.sub}))

           def make_app():
               return tornado.web.Application(
                   auth.get_handlers(prefix="/api") + [
                       (r"/protected", ProtectedHandler),
                   ]
               )

    .. tab-item::

        .. code-block:: python

           from typing import Dict
           from litestar import Litestar, get
           from py_oidc_auth import LitestarOIDCAuth

           auth = LitestarOIDCAuth(
                client_id="my client",
                client_secret="secret",
                discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
                scopes="myscope profile email",
           )

           @get("/protected")
           @auth.required()
           async def protected(token: IDToken) -> Dict[str, str]:
               return {"sub": token.sub}

           app = Litestar(
               route_handlers=[
                   protected,
                   \*auth.get_route_handlers(prefix="/api"),
               ]
           )

Scopes and claim constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All adapters support:

* ``scopes="a b c"`` to require scopes on a protected endpoint
* ``claims={...}`` to enforce simple claim constraints

FastAPI Example:

.. code-block:: python

   @auth.required(scopes="admin", claims={"groups": ["admins"]})
   def admin(token: IDToken) -> Dict[str, str]:
       return {"sub": token.sub}

Documentation
~~~~~~~~~~~~~

.. toctree::
   :maxdepth: 1
   :caption: Contents

   examples/index
   api/index
   whatsnew
   code-of-conduct

.. seealso::

   `py-oidc-auth-client (client library) <https://pypi.org/project/py-oidc-auth-client/>`_
