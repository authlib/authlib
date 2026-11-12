Breaking changes
~~~~~~~~~~~~~~~~

- ``ResourceProtector`` responds with HTTP 401, a ``WWW-Authenticate: Bearer``
  header and no error code to a request without ``Authorization`` header or
  with an unsupported scheme, per :rfc:`6750#section-3.1`. It used to send a
  ``missing_authorization`` or ``unsupported_token_type`` error. Both cases
  raise ``MissingAuthorizationError``, so with ``optional=True``, an
  unsupported scheme counts as a missing token.
  :pr:`956`
