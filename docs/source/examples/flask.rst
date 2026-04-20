Flask integration
=================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[flask]
   conda install -c conda-forge py-oidc-auth-flask

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from flask import Flask, Response, jsonify
   from py_oidc_auth import FlaskOIDCAuth

   app = Flask(__name__)

   auth = FlaskOIDCAuth(
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

   # Get the blueprint — a standard Flask Blueprint
   auth_bp = auth.create_auth_blueprint(prefix="/api")

   # Add your own custom endpoints to the auth blueprint
   @auth_bp.route("/auth/v2/auth-ports")
   def auth_ports() -> Response:
       """Expose valid redirect ports for client discovery."""
       return jsonify({"valid_ports": [8080, 8443]})

   # Register the blueprint in the app
   app.register_blueprint(auth_bp)

Protecting routes
^^^^^^^^^^^^^^^^^

Flask uses decorators.
The wrapped view receives the validated token as its first positional argument.

.. code-block:: python

   from typing import Optional
   from flask import Flask, Response, jsonify
   from py_oidc_auth import IDToken

   @app.get("/me")
   @auth.required()
   def me(token: IDToken) -> Response:
       return jsonify({"sub": token.sub})

   @app.get("/maybe_me")
   @auth.optional()
   def maybe_me(token: Optional[IDToken]) -> Response:
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
    from py_oidc_auth import MongoDBBrokerStore, FlaskOIDCAuth

    mongo_client = AsyncMongoClient("mongodb://myser:mypass@host")
    auth = FlaskOIDCAuth(
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

The router created by :meth:`~py_oidc_auth.fastapi_auth.FlaskOIDCAuth.create_auth_blueprint`
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

   POST /api/auth/v2/token HTTP/1.1
   Host: app.example.org
   Content-Type: application/x-www-form-urlencoded

   refresh_token=ref
