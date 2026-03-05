Litestar integration
====================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[litestar]
   conda install -c conda-forge py-oidc-auth-litestar

Minimal application
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from typing import Optional
   from litestar import Litestar, get
   from py_oidc_auth import LitestarOIDCAuth, IDToken

   auth = LitestarOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
   )

   @get("/me", dependencies={"token": auth.required()})
   async def me(token: IDToken) -> Dict[str, str]:
       return {"sub": token.sub}

   app = Litestar(route_handlers=[auth.create_auth_router(prefix=""), me])

Notes
^^^^^

Litestar uses dependency injection.
``required()`` and ``optional()`` return :class:`litestar.di.Provide` objects.
