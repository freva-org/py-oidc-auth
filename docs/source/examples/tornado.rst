Tornado integration
===================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: text

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
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
   )

   class MeHandler(tornado.web.RequestHandler):
       @auth.required()
       async def get(self, token: IDToken) -> None:
           self.write(json.dumps({"sub": token.sub}))

   def make_app():
       return tornado.web.Application(
           [
               (r"/me", MeHandler),
               *auth.get_urlpatterns(prefix=""),
           ]
       )

   if __name__ == "__main__":
       make_app().listen(8080)
       tornado.ioloop.IOLoop.current().start()

Notes
^^^^^

The Tornado adapter exposes ``get_urlpatterns`` for auth endpoints and decorator
helpers for handler methods.
