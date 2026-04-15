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
