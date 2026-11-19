Security
~~~~~~~~

- The client registration endpoint rejects a ``jwks`` that contains a private
  key. A crafted RSA private key could use tens of seconds of CPU at import.
