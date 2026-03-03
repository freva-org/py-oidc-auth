FastAPI integration
===================

Install
^^^^^^^

.. code-block:: text

   pip install py-oidc-auth[fastapi]

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from fastapi import FastAPI
   from py_oidc_auth import FastApiOIDCAuth

   app = FastAPI()

   auth = FastApiOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="openid profile email",
   )

   app.include_router(auth.create_auth_router(prefix=""))

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

Standard auth endpoints
^^^^^^^^^^^^^^^^^^^^^^^

The router created by :meth:`py_oidc_auth.fastapi_auth.FastApiOIDCAuth.create_auth_router`
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

Request examples
^^^^^^^^^^^^^^^^

.. code-block:: text

   GET /auth/v2/login?redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback HTTP/1.1
   Host: app.example.org

.. code-block:: text

   GET /auth/v2/callback?code=abc&state=xyz HTTP/1.1
   Host: app.example.org

.. code-block:: text

   POST /auth/v2/token HTTP/1.1
   Host: app.example.org
   Content-Type: application/x-www-form-urlencoded

   code=abc&redirect_uri=https%3A%2F%2Fapp.example.org%2Fcallback
