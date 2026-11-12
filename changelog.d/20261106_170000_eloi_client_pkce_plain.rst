Breaking changes
~~~~~~~~~~~~~~~~

- The OAuth 2 clients raise a ``ValueError`` when ``code_challenge_method`` is
  not ``S256`` or ``plain``. They used to skip PKCE. :issue:`709`

Fixed
~~~~~

- The OAuth 2 clients support the ``plain`` PKCE method, and add the PKCE
  challenge for a ``response_type`` that contains ``code``, such as
  ``code id_token``. They used to send a ``code_verifier`` without
  ``code_challenge``, and the server rejected the request. :issue:`709`
