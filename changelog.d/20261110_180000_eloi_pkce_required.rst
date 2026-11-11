Added
~~~~~

- ``CodeChallenge.is_code_challenge_required`` tells whether a client must use
  PKCE. Override it to require PKCE for all clients, as recommended by
  :rfc:`RFC 9700 §2.1.1 <9700#section-2.1.1>`. The codes issued without
  ``code_challenge`` are then rejected at the token endpoint. :issue:`1012`

Deprecated
~~~~~~~~~~

- The ``required`` parameter of ``CodeChallenge`` is deprecated. Override
  ``is_code_challenge_required`` instead. It will stop working in version
  1.11.
