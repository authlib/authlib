Fixed
~~~~~

- ``OpenIDProviderMetadata.validate()`` checks the RFC 8414 metadata too:
  the revocation and introspection endpoints, their authentication methods
  and algorithms, and ``code_challenge_methods_supported``.
