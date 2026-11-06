Added
~~~~~

- Grants and grant extensions declare the authorization request parameters
  they introduce, with ``register_authorization_parameters``. Server extensions
  use ``AuthorizationServer.register_authorization_parameters``.

Fixed
~~~~~

- An authorization request that repeats a parameter of an extension, such as
  ``nonce`` or ``code_challenge``, gets an ``invalid_request`` error
  (RFC 6749 §3.1). Only the RFC 6749 parameters used to be checked.
