Fixed
~~~~~

- ``AuthorizationServer.create_token_response`` and
  ``create_endpoint_response`` return an ``insecure_transport`` error response
  for a plain HTTP request, instead of raising ``InsecureTransportError``.
