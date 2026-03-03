Quart integration
=================

Install
^^^^^^^

.. code-block:: text

   pip install py-oidc-auth[quart]

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from quart import Quart
   from py_oidc_auth import QuartOIDCAuth

   app = Quart(__name__)

   auth = QuartOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="openid profile email",
   )

   app.register_blueprint(auth.create_auth_blueprint(prefix=""))

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
