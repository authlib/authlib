Breaking changes
~~~~~~~~~~~~~~~~

- The client integrations raise ``InvalidIDTokenError`` when the ID token is
  invalid, or when the provider JWK set holds invalid keys. It is an
  ``OAuthError``, so ``except AuthlibBaseError`` catches it again, as before
  1.7. Its ``error`` and ``description`` come from the ``joserfc`` error, which
  is available as ``__cause__``. Since 1.7, ``parse_id_token`` and
  ``authorize_access_token`` raised the ``joserfc`` errors directly. An
  unknown ``kid`` without ``jwks_uri`` raised a ``RuntimeError``.
  :issue:`966`
