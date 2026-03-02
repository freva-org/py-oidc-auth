.. image:: _static/logo.png
   :alt: py-oidc-auth logo
   :width: 560px
   :align: center

.. centered:: *A small, typed OpenID Connect helper for authentication and authorization.*

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

Pick your framework for installation:

.. code-block:: console

   python -m pip install py-oidc-auth[fastapi]
   python -m pip install py-oidc-auth[flask]
   python -m pip install py-oidc-auth[quart]
   python -m pip install py-oidc-auth[tornado]
   python -m pip install py-oidc-auth[litestar]
   python -m pip install py-oidc-auth[django]

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
       scopes="openid profile email",
   )

FastAPI
^^^^^^^

.. code-block:: python

   from typing import Optional

   from fastapi import FastAPI
   from py_oidc_auth import FastApiOIDCAuth
   from py_oidc_auth.schema import IDToken

   app = FastAPI()

   auth = FastApiOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="openid profile email",
   )

   app.include_router(auth.create_auth_router(prefix="/api"))

   @app.get("/me")
   async def me(token: IDToken = auth.required()):
       return {"sub": token.sub}

   @app.get("/feed")
   async def feed(token: Optional[IDToken] = auth.optional()):
       return {"authenticated": token is not None}

Flask
^^^^^

.. code-block:: python

   from flask import Flask
   from py_oidc_auth import FlaskOIDCAuth

   app = Flask(__name__)

   auth = FlaskOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
   )

   app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

   @app.get("/protected")
   @auth.required()
   def protected(token):
       return {"sub": token.sub}

Quart
^^^^^

.. code-block:: python

   from quart import Quart
   from py_oidc_auth import QuartOIDCAuth

   app = Quart(__name__)

   auth = QuartOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
   )

   app.register_blueprint(auth.create_auth_blueprint(prefix="/api"))

   @app.get("/protected")
   @auth.required()
   async def protected(token):
       return {"sub": token.sub}

Django
^^^^^^

Decorator style:

.. code-block:: python

   from django.http import JsonResponse
   from django.urls import path
   from py_oidc_auth import DjangoOIDCAuth

   auth = DjangoOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
   )

   @auth.required()
   async def protected_view(request, token):
       return JsonResponse({"sub": token.sub})

   urlpatterns = [
       *auth.get_urlpatterns(prefix="api"),
       path("protected/", protected_view),
   ]

Routes only:

.. code-block:: python

   urlpatterns = [
       *auth.get_urlpatterns(prefix="api"),
   ]

Tornado
^^^^^^^

.. code-block:: python

   import tornado.web
   from py_oidc_auth import TornadoOIDCAuth

   auth = TornadoOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
   )

   class ProtectedHandler(tornado.web.RequestHandler):
       @auth.required()
       async def get(self, token):
           self.write({"sub": token.sub})

   def make_app():
       return tornado.web.Application(
           auth.get_handlers(prefix="/api") + [
               (r"/protected", ProtectedHandler),
           ]
       )

Litestar
^^^^^^^^

.. code-block:: python

   from litestar import Litestar, get
   from py_oidc_auth import LitestarOIDCAuth

   auth = LitestarOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
   )

   @get("/protected")
   @auth.required()
   async def protected(token):
       return {"sub": token.sub}

   app = Litestar(
       route_handlers=[
           protected,
           *auth.get_route_handlers(prefix="/api"),
       ]
   )

Scopes and claim constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All adapters support:

* ``scopes="a b c"`` to require scopes on a protected endpoint
* ``claims={...}`` to enforce simple claim constraints

Example:

.. code-block:: python

   @auth.required(scopes="admin", claims={"groups": ["admins"]})
   def admin(token):
       return {"sub": token.sub}

Documentation
~~~~~~~~~~~~~

.. toctree::
   :maxdepth: 1
   :caption: Contents

   examples/index
   api/index
