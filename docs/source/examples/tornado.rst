Tornado integration
===================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[tornado]
   conda install -c conda-forge py-oidc-auth-tornado

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   import json
   import tornado.web
   import tornado.ioloop
   from py_oidc_auth import TornadoOIDCAuth, IDToken

   auth = TornadoOIDCAuth(
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

   # Custom handler alongside the standard OIDC routes
   class AuthPortsHandler(tornado.web.RequestHandler):
       """Expose valid redirect ports for client discovery."""
       def get(self) -> None:
           self.write(json.dumps({"valid_ports": [8080, 8443]}))

   class MeHandler(tornado.web.RequestHandler):
       @auth.required()
       async def get(self, token: IDToken) -> None:
           self.write(json.dumps({"sub": token.sub}))

   def make_app():
       return tornado.web.Application(
           [
               *auth.get_auth_routes(prefix="/api"),
               (r"/api/auth/v2/auth-ports", AuthPortsHandler),
               (r"/me", MeHandler),
           ]
       )

   if __name__ == "__main__":
       make_app().listen(8080)
       tornado.ioloop.IOLoop.current().start()

Reusing database objects for token storage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using `broker_mode=True` the Identity Provider (IdP) tokens will be stored
securely in a database. Instead of creating new database instances already
existing database objects can be used to create a
:class:`py_oidc_auth.broker.store.BrokerStore` object. The following example
uses an existing MongoDB connection:


.. code-block:: python

    from pymongo import AsyncMongoClient
    from py_oidc_auth import MongoDBBrokerStore, TornadoOIDCAuth

    mongo_client = AsyncMongoClient("mongodb://myser:mypass@host")
    auth = TornadoOIDCAuth(
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

The router created by :meth:`~py_oidc_auth.TornadoOIDCAuth.get_auth_routes`
exposes these endpoints by default:

.. http:get:: /auth/v2/login

   Starts the authorization code flow. Send ``code_challenge`` (S256) and
   ``state``; without them the server keeps the verifier in ``state``.

.. http:get:: /auth/v2/callback

   Receives ``code`` and ``state`` from the provider.

.. http:post:: /auth/v2/token

   Exchanges an authorization code (with ``code_verifier``), refreshes
   (``refresh_token``) or polls the device flow (``device_code``, with
   ``code_verifier``). Token responses include the provider's ``id_token``.

.. http:post:: /auth/v2/device

   Starts the device authorization flow; send ``code_challenge`` to bind it
   to your verifier.

.. http:get:: /auth/v2/logout

   Redirects to the provider logout endpoint. Pass ``id_token_hint`` to
   skip the provider's confirmation page.

.. http:get:: /auth/v2/userinfo

   Calls the provider userinfo endpoint.

.. http:get:: /api/auth/v2/.well-known/jwks.json

   Broker public key (broker mode only)


Notes
^^^^^

The Tornado adapter exposes ``get_auth_routes`` which returns a list of
``(pattern, handler_class, init_kwargs)`` tuples. Combine them with your own
handlers using standard list concatenation.


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
