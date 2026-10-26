Fixed
~~~~~

- ``parse_id_token`` and ``authorize_access_token`` in the client integrations
  raise ``InvalidIDTokenError``, an ``OAuthError``, when the ID token can not be
  decoded or validated. Since 1.7 they raised plain ``joserfc`` errors that
  ``except AuthlibBaseError`` did not catch. The new error is also an instance
  of the original ``joserfc`` exception, so existing handlers keep working.
  :issue:`966`
