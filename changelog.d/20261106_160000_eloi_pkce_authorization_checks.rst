Fixed
~~~~~

- When PKCE is required, the authorization endpoint rejects a public client
  without ``code_challenge``, per :rfc:`7636#section-4.4.1`. The error used to
  come only at the token endpoint, after the login and the consent.
- The authorization endpoint rejects a request without
  ``code_challenge_method`` when ``plain`` is not in
  ``SUPPORTED_CODE_CHALLENGE_METHOD``. Per :rfc:`7636#section-4.3`, a missing
  method means ``plain``. Such requests used to be accepted with ``plain``.
