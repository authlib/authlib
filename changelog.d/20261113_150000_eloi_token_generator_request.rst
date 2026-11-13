Added
~~~~~

- Token generators receive the current request as ``request``.
  ``JWTBearerTokenGenerator.get_auth_time``, ``get_acr`` and ``get_amr`` receive it instead of the user.
  They can return the values of the authentication that the token comes from, such as the ones stored on the authorization code.
  ``get_extra_claims``, ``get_audiences`` and ``get_jti`` receive it as a last ``request`` argument.

Deprecated
~~~~~~~~~~

- Token generators without a ``request`` parameter are deprecated.
  In 1.11, they will always receive it.
  This applies to the functions given to ``register_token_generator``, to ``OAUTH2_ACCESS_TOKEN_GENERATOR`` and ``OAUTH2_REFRESH_TOKEN_GENERATOR`` (Flask), and to ``access_token_generator`` and ``refresh_token_generator`` (Django).
  It also applies to the overrides of ``AuthorizationServer.generate_token``, ``BearerTokenGenerator.generate``, and ``JWTBearerTokenGenerator.access_token_generator``, ``get_extra_claims``, ``get_audiences`` and ``get_jti``.
- Access token generators without an ``expires_in`` parameter are deprecated.
  In 1.11, they will always receive it.
- ``JWTBearerTokenGenerator.get_auth_time``, ``get_acr`` and ``get_amr`` overrides that take the user are deprecated.
  In 1.11, they will receive the request.
