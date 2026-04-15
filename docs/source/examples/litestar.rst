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

   from typing import Dict, List
   from litestar import Litestar, get
   from py_oidc_auth import LitestarOIDCAuth, IDToken

   auth = LitestarOIDCAuth(
       client_id="my-client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
       audience="my-aud",
   )

   # Custom endpoint alongside the standard OIDC routes
   @get("/auth/v2/auth-ports")
   async def auth_ports() -> Dict[str, List[int]]:
       """Expose valid redirect ports for client discovery."""
       return {"valid_ports": [8080, 8443]}

   @get("/me", dependencies={"token": auth.required()})
   async def me(token: IDToken) -> Dict[str, str]:
       return {"sub": token.sub}

   # Combine the auth router with your own handlers
   app = Litestar(
       route_handlers=[
           auth.create_auth_router(prefix="/api"),
           auth_ports,
           me,
       ]
   )

Notes
^^^^^

Litestar uses dependency injection.
``required()`` and ``optional()`` return :class:`litestar.di.Provide` objects.
The auth router returned by ``create_auth_router`` is a standard
:class:`litestar.Router` that can be combined with other route handlers.
