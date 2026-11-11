Fixed
~~~~~

- ``AssertionSession``, ``ClientSecretJWT`` and ``PrivateKeyJWT`` send a new
  ``jti`` with every assertion when they are given ``claims``. The generated
  ``jti`` used to be written into the ``claims`` dict and sent again on every
  later request, so identity providers that check ``jti`` rejected the second
  token request as a replay.
