Breaking changes
~~~~~~~~~~~~~~~~

- Revocation and introspection endpoints ignore an unknown ``token_type_hint``
  value, per :rfc:`7009#section-2.2` and :rfc:`7662#section-2.1`. They used to
  respond with an ``unsupported_token_type`` error.
- ``UnsupportedTokenTypeError`` responds with HTTP 400, per
  :rfc:`7009#section-2.2.1`. It used to respond with HTTP 401. It is only
  raised when the token type cannot be revoked, like a JWT access token.
  It now inherits from ``OAuth2Error`` instead of ``ForbiddenError``, so it
  no longer takes ``auth_type`` and ``realm`` arguments.
