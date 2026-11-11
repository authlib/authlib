Breaking changes
~~~~~~~~~~~~~~~~

- The OAuth 2 clients raise a ``ValueError`` when ``code_challenge_method`` is
  not ``S256`` or ``plain``. They used to skip PKCE for other values.

Fixed
~~~~~

- The OAuth 2 clients support the ``plain`` PKCE method (issue #709). They
  also add the PKCE challenge for a ``response_type`` that contains ``code``,
  such as ``code id_token``. In both cases, the clients used to send a
  ``code_verifier`` without ``code_challenge``, and the server rejected the
  request.
