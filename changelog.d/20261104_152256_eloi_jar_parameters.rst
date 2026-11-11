Added
~~~~~

- ``AuthorizationServer.authorization_parameters`` gives the RFC 6749
  parameters and those of the server extensions, with their JSON types.

Fixed
~~~~~

- An authorization request that repeats an RFC 6749 parameter or a parameter
  of a server extension, such as ``client_id``, ``request`` or
  ``request_uri``, gets an ``invalid_request`` error before the grant is
  chosen. With JAR, the request object is not fetched or decoded.
