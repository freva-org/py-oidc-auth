Litestar integration
====================

Install
^^^^^^^

.. code-block:: text

   pip install py-oidc-auth[litestar]

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from litestar import Litestar, get
   from py_oidc_auth import LitestarOIDCAuth

   auth = LitestarOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="openid profile email",
   )

   @get("/me", dependencies={"token": auth.required()})
   async def me(token):
       return {"sub": token.sub}

   app = Litestar(route_handlers=[auth.create_auth_router(prefix=""), me])

Notes
^^^^^

Litestar uses dependency injection.
``required()`` and ``optional()`` return :class:`litestar.di.Provide` objects.
