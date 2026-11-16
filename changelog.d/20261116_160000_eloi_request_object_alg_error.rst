Changed
~~~~~~~

- Some authorization errors now use the code that the specifications define:
  ``invalid_request`` without ``response_type`` (RFC 6749 §4.1.2.1), and
  ``invalid_request_object`` for a request object ``alg`` that the server does
  not accept (RFC 9101 §6.2).
