Added
~~~~~

- ``JWTAuthenticationRequest.resolve_client_secret`` returns the client secret
  that verifies Request Objects signed with ``HS256``, ``HS384`` or ``HS512``
  (OpenID Connect Core §10.1).

Breaking changes
~~~~~~~~~~~~~~~~

- Request Objects signed with an HMAC algorithm are only verified with the
  secret from ``JWTAuthenticationRequest.resolve_client_secret``, never with
  the keys from ``resolve_client_public_key``. By default, they are rejected.
