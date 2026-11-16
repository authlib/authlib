Fixed
~~~~~

- The Flask ``AuthorizationServer`` processes the ``request`` given to its
  methods, such as ``get_consent_grant`` and ``create_token_response``. It
  used to process the current Flask request in all cases.
