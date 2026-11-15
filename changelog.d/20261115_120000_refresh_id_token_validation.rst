Added
~~~~~

- ``parse_id_token`` accepts the claims of the original ID token as ``original``,
  to validate the ID token of a refresh token response against its ``iss``,
  ``sub``, ``aud`` and ``auth_time`` (OpenID Connect Core §12.2). :issue:`1044`
