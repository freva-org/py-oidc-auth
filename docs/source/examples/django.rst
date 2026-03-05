Django integration
==================

Install
^^^^^^^

Install with pip or conda/mamba/micromamba

.. code-block:: console

   pip install py-oidc-auth[django]
   conda install -c conda-forge py-oidc-auth-django

Wiring URL patterns
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from django.urls import path
   from py_oidc_auth import DjangoOIDCAuth

   auth = DjangoOIDCAuth(
       client_id="my client",
       client_secret="secret",
       discovery_url="https://idp.example.org/realms/demo/.well-known/openid-configuration",
       scopes="myscope profile email",
   )

   urlpatterns = [
       *auth.get_urlpatterns(prefix=""),
   ]

Protecting views
^^^^^^^^^^^^^^^^

The wrapped view receives the validated token as an additional argument after
the request object.
Both sync and async views are supported.

.. code-block:: python

   from django.http import HttpRequest, JsonResponse
   from py_oidc_auth import IDToken

   @auth.required()
   def me(request: HttpRequest, token: IDToken) -> JsonResponse:
       return JsonResponse({"sub": token.sub})

   @auth.optional()
   async def maybe_me(request: HttpRequest, token: IDToken) -> JsonResponse:
       if token is None:
           return JsonResponse({"anonymous": True})
       return JsonResponse({"sub": token.sub})
