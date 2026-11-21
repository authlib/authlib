Fixed
~~~~~

- Resolve the requested scope once via ``client.get_allowed_scope()`` in each
  grant (and in ``DeviceAuthorizationEndpoint``) instead of resolving it again
  in ``BearerTokenGenerator`` and ``JWTBearerTokenGenerator``. Clients whose
  ``get_allowed_scope()`` returns a default scope for an empty value no longer
  expand an already-resolved empty scope back into the default scope at token
  generation time. :issue:`1066`

Deprecated
~~~~~~~~~~

- ``BearerTokenGenerator.get_allowed_scope()`` is deprecated and will be
  removed in 1.11. Grants now resolve the scope before calling the token
  generator.
