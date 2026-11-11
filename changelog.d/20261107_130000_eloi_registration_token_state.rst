Fixed
~~~~~

- The RFC 7591 and RFC 7592 endpoints do not check if a token is expired or
  revoked, so ``authenticate_token`` must return ``None`` for such tokens. The
  docstrings and the documentation examples now say so.
