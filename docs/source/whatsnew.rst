What's new
==========

This document highlights major changes and additions across releases.

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
