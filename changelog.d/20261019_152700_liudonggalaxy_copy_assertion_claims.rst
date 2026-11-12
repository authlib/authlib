Fixed
~~~~~

- ``AssertionSession``, ``ClientSecretJWT`` and ``PrivateKeyJWT`` send a new
  ``jti`` with each assertion when they are given ``claims``. They used to
  send the first ``jti`` again, and providers that check it rejected the next
  token requests as replays. :pr:`965`
