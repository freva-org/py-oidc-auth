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
