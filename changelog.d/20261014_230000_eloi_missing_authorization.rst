Breaking changes
~~~~~~~~~~~~~~~~

- A request to a resource protected by ``ResourceProtector`` without
  ``Authorization`` header, or with an unsupported authentication scheme, gets
  an HTTP 401 response with a ``WWW-Authenticate: Bearer`` header and no error
  code, per :rfc:`6750#section-3.1`. The response used to contain a
  ``missing_authorization`` or ``unsupported_token_type`` error. Both cases
  raise ``MissingAuthorizationError``, so a resource with ``optional=True``
  treats an unsupported scheme like a request without token.
