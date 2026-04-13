What's new
==========

This document highlights major changes and additions across releases.


v2604.0.0
---------
* Add ``verify_exp``, ``verify_iss``, ``verify_aud``, ``verify_nbf`` flags to
  ``OIDCAuth``, ``OIDCConfig``, and ``TokenVerifier`` to allow disabling
  individual JWT claim checks. All flags default to ``True``


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
