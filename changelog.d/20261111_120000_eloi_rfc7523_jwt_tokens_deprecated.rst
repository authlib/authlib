Deprecated
~~~~~~~~~~

- ``authlib.oauth2.rfc7523.JWTBearerTokenGenerator`` and
  ``authlib.oauth2.rfc7523.JWTBearerTokenValidator`` are deprecated. They use a
  custom JWT access token format, which :rfc:`9068` now standardizes. Use the
  classes of the same name in ``authlib.oauth2.rfc9068`` instead. The generator
  will be removed in 1.11, and the validator in 2.0. :issue:`846`
