Litestar integration
====================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[litestar]
   conda install -c conda-forge py-oidc-auth-litestar

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from typing import Dict, List
   from litestar import Litestar, get
   from py_oidc_auth import LitestarOIDCAuth, IDToken

   auth = LitestarOIDCAuth(
       client_id="my-client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
       audience="my-aud",
       broker_mode=True,
       broker_store_url="postgresql+asyncpg://user:pw@db/myapp",
       broker_audience="myapp-api",
       trusted_issuers=["https://other-instance.example.org"],
   )

   # Custom endpoint alongside the standard OIDC routes
   @get("/auth/v2/auth-ports")
   async def auth_ports() -> Dict[str, List[int]]:
       """Expose valid redirect ports for client discovery."""
       return {"valid_ports": [8080, 8443]}

   @get("/me", dependencies={"token": auth.required()})
   async def me(token: IDToken) -> Dict[str, str]:
       return {"sub": token.sub}

   # Combine the auth router with your own handlers
   app = Litestar(
       route_handlers=[
           auth.create_auth_router(prefix="/api"),
           auth_ports,
           me,
       ]
   )


Reusing database objects for token storage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using `broker_mode=True` the Identity Provider (IdP) tokens will be stored
securely in a database. Instead of creating new database instances already
existing database objects can be used to create a
:class:`py_oidc_auth.broker.store.BrokerStore` object. The following example
uses an existing MongoDB connection:


.. code-block:: python

    from pymongo import AsyncMongoClient
    from py_oidc_auth import MongoDBBrokerStore, LitestarOIDCAuth

    mongo_client = AsyncMongoClient("mongodb://myser:mypass@host")
    auth = LitestarOIDCAuth(
       client_id="my-client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
       audience="my-aud",
       broker_mode=True,
       broker_store_obj=MongoDBBrokerStore(db=mongo_client["my-app"]),
       broker_audience="myapp-api",
       trusted_issuers=["https://other-instance.example.org"],
   )


Standard auth endpoints
^^^^^^^^^^^^^^^^^^^^^^^

The router created by :meth:`~py_oidc_auth.LitestarOIDCAuth.create_auth_blueprint`
exposes these endpoints by default:

.. http:get:: /auth/v2/login

   Starts the authorization code flow.

.. http:get:: /auth/v2/callback

   Receives ``code`` and ``state`` from the provider.

.. http:post:: /auth/v2/token

   Exchanges an authorization code or refresh token.

.. http:post:: /auth/v2/device

   Starts the device authorization flow.

.. http:get:: /auth/v2/logout

   Redirects to the provider logout endpoint.

.. http:get:: /auth/v2/userinfo

   Calls the provider userinfo endpoint.

.. http:get:: /api/auth/v2/.well-known/jwks.json

   Broker public key (broker mode only)



Notes
^^^^^

Litestar uses dependency injection.
``required()`` and ``optional()`` return :class:`litestar.di.Provide` objects.
The auth router returned by ``create_auth_router`` is a standard



Request examples
^^^^^^^^^^^^^^^^

.. code-block:: text

   GET /api/auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
   Host: app.example.org

.. code-block:: text

   GET /api/auth/v2/callback?code=abc&state=xyz HTTP/1.1
   Host: app.example.org

.. code-block:: text

   POST /api/auth/v2/token HTTP/1.1
   Host: app.example.org
   Content-Type: application/x-www-form-urlencoded

   code=abc&redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback
:class:`litestar.Router` that can be combined with other route handlers.
