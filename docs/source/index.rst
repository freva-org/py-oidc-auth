py-oidc-auth
============

py-oidc-auth is a reusable OpenID Connect authentication library.

It provides a small framework independent core plus optional integrations for
popular Python web frameworks.

py-oidc-auth helps you add OpenID Connect login and bearer token validation to a
web service with minimal boilerplate.

What you get
^^^^^^^^^^^^

* A framework independent core :class:`py_oidc_auth.auth_base.OIDCAuth`
* Standard authentication endpoints that you can mount into your app
* A decorator style API for protected and optional routes

Core concepts
^^^^^^^^^^^^^

Provider discovery
  You provide a discovery URL (the well known OpenID configuration endpoint).
  The library downloads endpoints and JSON Web Key Sets (JWKS) as needed.

Standard endpoints
  Each framework integration can expose a small set of routes:

  * login
  * callback
  * token
  * device
  * logout
  * userinfo

  The default paths are the same across frameworks.

Decorator style protection
  Each framework integration offers:

  * ``required()`` for authenticated routes
  * ``optional()`` for routes that accept a bearer token when present

Installation
^^^^^^^^^^^^

Install a framework integration by selecting an extra:

.. code-block:: text

   pip install py-oidc-auth[fastapi]
   pip install py-oidc-auth[flask]
   pip install py-oidc-auth[quart]
   pip install py-oidc-auth[tornado]
   pip install py-oidc-auth[litestar]
   pip install py-oidc-auth[django]

Quick pattern
^^^^^^^^^^^^^

Most apps follow this pattern:

#. Create an auth instance with ``client_id`` and ``discovery_url``.
#. Mount the auth routes in your app.
#. Protect endpoints with ``required()`` or ``optional()``.

See the framework examples for complete working snippets.

Contents
^^^^^^^^

.. toctree::
   :maxdepth: 1

   examples/index
   api/index
