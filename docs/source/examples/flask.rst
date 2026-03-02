Flask integration
=================

Install
^^^^^^^

.. code-block:: text

   pip install py-oidc-auth[flask]

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from flask import Flask
   from py_oidc_auth import FlaskOIDCAuth

   app = Flask(__name__)

   auth = FlaskOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="openid profile email",
   )

   app.register_blueprint(auth.create_auth_blueprint(prefix=""))

Protecting routes
^^^^^^^^^^^^^^^^^

Flask uses decorators.
The wrapped view receives the validated token as its first positional argument.

.. code-block:: python

   @app.get("/me")
   @auth.required()
   def me(token):
       return {"sub": token.sub}

   @app.get("/maybe_me")
   @auth.optional()
   def maybe_me(token):
       if token is None:
           return {"anonymous": True}
       return {"sub": token.sub}

Request examples
^^^^^^^^^^^^^^^^

.. code-block:: text

   GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
   Host: app.example.org

.. code-block:: text

   POST /auth/v2/token HTTP/1.1
   Host: app.example.org
   Content-Type: application/x-www-form-urlencoded

   refresh_token=ref
