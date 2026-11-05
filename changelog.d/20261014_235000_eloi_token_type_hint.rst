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
- The :rfc:`9068` revocation and introspection endpoints handle a JWT only if
  its ``typ`` header is ``at+jwt``, per :rfc:`9068#section-2.1`. They no
  longer use the ``token_type_hint``. A JWT access token sent with a
  ``refresh_token`` hint is now handled. Other JWTs, like JWT refresh tokens,
  go to the next endpoint.
- The SQLAlchemy revocation endpoint no longer uses the ``token_type_hint``.
  Revoking an access token keeps the refresh token active, with or without a
  hint. Revoking a refresh token also revokes the access token, per
  :rfc:`7009#section-2.1`.

Fixed
~~~~~

- Revocation and introspection endpoints search all token types when the
  token is not found with the ``token_type_hint``, per :rfc:`7009#section-2.1`
  and :rfc:`7662#section-2.1`. A refresh token sent with an ``access_token``
  hint used to be ignored, so it was not revoked. Custom
  ``revoke_token`` methods must not trust the hint to know which token was
  presented.
