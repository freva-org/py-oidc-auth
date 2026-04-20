Quart integration
=================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[quart]
   conda install -c conda-forge py-oidc-auth-quart

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from quart import Quart, Response, jsonify
   from py_oidc_auth import QuartOIDCAuth

   app = Quart(__name__)

   auth = QuartOIDCAuth(
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

   # Get the blueprint — a standard Quart Blueprint
   auth_bp = auth.create_auth_blueprint(prefix="/api")

   # Add your own custom endpoints to the auth blueprint
   @auth_bp.route("/auth/v2/auth-ports")
   async def auth_ports() -> Response:
       """Expose valid redirect ports for client discovery."""
       return jsonify({"valid_ports": [8080, 8443]})

   # Register the blueprint in the app
   app.register_blueprint(auth_bp)

Protecting routes
^^^^^^^^^^^^^^^^^

Quart route functions are async.
The wrapped view receives the validated token as its first positional argument.

.. code-block:: python

   from typing import Optional
   from py_oidc_auth import IDToken
   from quart import Response, jsonify

   @app.get("/me")
   @auth.required()
   async def me(token: IDToken) -> Response:
       return jsonify({"sub": token.sub})

   @app.get("/maybe_me")
   @auth.optional()
   async def maybe_me(token: Optional[IDToken]) -> Response:
       if token is None:
           return jsonify({"anonymous": True})
       return jsonify({"sub": token.sub})

Reusing database objects for token storage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using `broker_mode=True` the Identity Provider (IdP) tokens will be stored
securely in a database. Instead of creating new database instances already
existing database objects can be used to create a
:class:`py_oidc_auth.broker.store.BrokerStore` object. The following example
uses an existing MongoDB connection:


.. code-block:: python

    from pymongo import AsyncMongoClient
    from py_oidc_auth import MongoDBBrokerStore, QuartOIDCAuth

    mongo_client = AsyncMongoClient("mongodb://myser:mypass@host")
    auth = QuartOIDCAuth(
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

The router created by :meth:`~py_oidc_auth.QuartOIDCAuth.create_auth_blueprint`
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
:class:`litestar.Router` that can be combined with other route handlers.



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
