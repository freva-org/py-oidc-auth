FastAPI integration
===================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[fastapi]
   conda install -c conda-forge py-oidc-auth-fastapi

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from typing import Dict, List

   from fastapi import FastAPI
   from py_oidc_auth import FastApiOIDCAuth, IDToken

   app = FastAPI()

   auth = FastApiOIDCAuth(
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

   # Get the router — a standard FastAPI APIRouter
   auth_router = auth.create_auth_router(prefix="/api")

   # Add your own custom endpoints to the auth router
   @auth_router.get("/auth/v2/auth-ports")
   async def auth_ports() -> Dict[str, List[int]]:
       """Expose valid redirect ports for client discovery."""
       return {"valid_ports": [8080, 8443]}

   # Include the router in the app
   app.include_router(auth_router)

Protecting routes
^^^^^^^^^^^^^^^^^

FastAPI uses dependency injection.
Use ``token=auth.required()`` or ``token=auth.optional()``.

.. code-block:: python

   from typing import Dict, Optional
   from py_oidc_auth import IDToken

   @app.get("/me")
   async def me(token: IDToken = auth.required()) -> Dict[str, str]:
       return {"sub": token.sub}

   @app.get("/maybe_me")
   async def maybe_me(token: Optional[IDToken] = auth.optional()) -> Dict[str, str]:
       if token is None:
           return {"anonymous": True}
       return {"sub": token.sub}

Reusing database objects for token storage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using `broker_mode=True` the Identity Provider (IdP) tokens will be stored
securely in a database. Instead of creating new database instances already
existing database objects can be used to create a
:class:`py_oidc_auth.broker.store.BrokerStore` object. The following example
uses an existing MongoDB connection:


.. code-block:: python

    from pymongo import AsyncMongoClient
    from py_oidc_auth import MongoDBBrokerStore, FastApiOIDCAuth

    mongo_client = AsyncMongoClient("mongodb://myser:mypass@host")
    auth = FastApiOIDCAuth(
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

The router created by :meth:`~py_oidc_auth.fastapi_auth.FastApiOIDCAuth.create_auth_router`
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
