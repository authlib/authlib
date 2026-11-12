Breaking changes
~~~~~~~~~~~~~~~~

- Revocation and introspection endpoints ignore an unknown
  ``token_type_hint``, per :rfc:`7009#section-2.2` and
  :rfc:`7662#section-2.1`. They used to respond with
  ``unsupported_token_type``. :pr:`1006`
- Revocation and introspection endpoints search the other token types when
  the token is not found with the ``token_type_hint``, per
  :rfc:`7009#section-2.1` and :rfc:`7662#section-2.1`. A refresh token sent
  with an ``access_token`` hint used to stay active. Custom ``revoke_token``
  methods must not trust the hint. :pr:`1006`
- ``UnsupportedTokenTypeError`` responds with HTTP 400 instead of 401, per
  :rfc:`7009#section-2.2.1`. It inherits from ``OAuth2Error`` instead of
  ``ForbiddenError``, and no longer takes ``auth_type`` and ``realm``.
  :pr:`1006`
- The :rfc:`9068` revocation and introspection endpoints only handle JWTs with
  the ``at+jwt`` ``typ``, whatever the hint. Other JWTs, such as JWT refresh
  tokens, go to the next endpoint. :pr:`1006`
- The SQLAlchemy revocation endpoint ignores the hint. Revoking an access
  token keeps the refresh token active. Revoking a refresh token also revokes
  the access token, per :rfc:`7009#section-2.1`. :pr:`1006`
