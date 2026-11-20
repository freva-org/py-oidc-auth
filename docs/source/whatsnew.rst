What's new
==========

This document highlights major changes and additions across releases.

v2611.0.0
---------
* PKCE now protects logins: clients send their own ``code_challenge`` (S256)
  and ``state`` to ``/login`` and redeem the code at ``/token`` with their
  verifier. Logins without a challenge keep the old behaviour (verifier in
  ``state``, no protection) and log a warning;
  ``require_client_pkce=True`` refuses them and disables ``/callback``.
* Device flow: an optional ``code_challenge`` is forwarded to the provider,
  and ``code_verifier`` is sent with every poll.
* Token responses carry the provider's ``id_token`` (not in broker mode);
  ``/logout`` accepts ``id_token_hint``.
* ``/login``, ``/logout``, ``/device``, ``/token`` and ``/callback`` answer
  503 instead of 500 or 502 when the provider cannot be reached.
* ``/token`` accepts ``refresh_token`` and ``device_code`` besides the old
  ``refresh-token`` and ``device-code``.
* Depend on ``sqlalchemy[asyncio]``: importing the library failed without
  ``greenlet``.
* Litestar: the built in ``/userinfo`` marks its dependency explicitly
  (``NamedDependency``); requires ``litestar>=2.23``.

v2606.0.0
---------
* Fixed missing `openid` scope in device-code flow (operator-precedence bug)


v2605.0.0
---------
* improve error logging.
* make refresh token optional.



v2604.3.0
---------
* store payload from `userinfo` query to token store.

v2604.2.3
---------
* fixed `callback` endpoint pass through bug.

v2604.2.2
---------
* fixed `userinfo` endpoint pass through bug.

v2604.2.1
---------
* pull sqlalchemy and aiosqlit as default dependency

v2604.2.0
---------
* implemented token exchange flow
* implemented token broker / minting
* implemented token federation via trusted issuer


v2604.1.0
---------
* enable overriding of `jwks_uri` and `issuer`.
* improve claim checks by flattening various roles.

v2604.0.0
---------
* explicitly set audience.


v2603.0.2
---------
* filter None token claims before userinfo mapping


v2603.0.1
---------
* Remove redundant FastAPI Tags.
* Update documentation.


v2603.0.0
---------
* Improve scope handling.
* Make ``offline_access`` configurable for refresh token access.

v2602.0.1
---------
* Initial release.
