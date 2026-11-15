Fixed
~~~~~

- ``IntrospectionEndpoint`` reports a refresh token as active while the
  refresh token is valid, even if the access token stored in the same record
  is expired. ``TokenMixin`` has an optional ``is_refresh_token_expired``
  method, used when the request presents the refresh token. It falls back to
  ``is_expired``. ``OAuth2TokenMixin`` does not expire refresh tokens.
  :issue:`1053`
