Fixed
~~~~~

- ``create_authorization_response``, ``create_token_response`` and
  ``create_endpoint_response`` return an ``insecure_transport`` error response
  for a plain HTTP request. They used to raise ``InsecureTransportError``.
  :issue:`973`
