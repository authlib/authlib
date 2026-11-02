Added
~~~~~

- ``ClientSecretJWT`` and ``PrivateKeyJWT`` accept an ``expires_in`` parameter
  for the lifetime of the client assertion, which used to be hardcoded to
  3600 seconds. Identity providers that cap assertion lifetimes, such as
  Auth0's 5-minute limit for ``private_key_jwt``, can now be used without a
  custom client authentication subclass. :issue:`857`
