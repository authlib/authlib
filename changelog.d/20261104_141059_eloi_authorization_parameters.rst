Added
~~~~~

- Grants and extensions declare the authorization request parameters they add
  with ``register_authorization_parameters``.
  ``AuthorizationServer.authorization_parameters`` lists them with their JSON
  types. :pr:`992` :pr:`994`

Fixed
~~~~~

- An authorization request that repeats a parameter gets an
  ``invalid_request`` error, per RFC 6749 §3.1. Only the RFC 6749 parameters
  used to be checked. This now covers the parameters of the extensions, such
  as ``nonce``, ``code_challenge`` or ``request_uri``. With JAR, the request
  object is then not fetched. :pr:`992` :pr:`994`
