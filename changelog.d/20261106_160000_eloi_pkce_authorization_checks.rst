Added
~~~~~

- ``CodeChallenge.is_code_challenge_required`` tells whether a client must use
  PKCE. Override it to require PKCE for all clients, as recommended by
  :rfc:`RFC 9700 §2.1.1 <9700#section-2.1.1>`. :issue:`1012`

Fixed
~~~~~

- When PKCE is required, the authorization endpoint rejects a public client
  without ``code_challenge``, per :rfc:`7636#section-4.4.1`. The error used to
  come at the token endpoint, after the login and the consent. :pr:`1013`
- The authorization endpoint rejects a request without
  ``code_challenge_method`` when ``plain`` is not supported. Per
  :rfc:`7636#section-4.3`, a missing method means ``plain``. Such requests
  used to be accepted. :pr:`1013`

Deprecated
~~~~~~~~~~

- The ``required`` parameter of ``CodeChallenge`` is deprecated. Override
  ``is_code_challenge_required`` instead. It will stop working in 1.11.
  :issue:`1012`
