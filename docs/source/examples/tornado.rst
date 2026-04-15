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

Notes
^^^^^

The Tornado adapter exposes ``get_auth_routes`` which returns a list of
``(pattern, handler_class, init_kwargs)`` tuples. Combine them with your own
handlers using standard list concatenation.
