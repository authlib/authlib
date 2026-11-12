Fixed
~~~~~

- The documentation of the RFC 7591 and RFC 7592 endpoints says that
  ``authenticate_token`` must return ``None`` for an expired or revoked token.
  The endpoints do not check it.
