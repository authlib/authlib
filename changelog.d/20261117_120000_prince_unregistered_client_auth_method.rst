Fixed
~~~~~

- An OAuth 2.0 client with a ``token_endpoint_auth_method`` that is not
  registered, such as ``client_secret_jwt`` without
  ``register_client_auth_method``, raises a ``ValueError`` that names the
  method. It used to raise ``TypeError: 'str' object is not callable``.
  :issue:`584`
