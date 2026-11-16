Changed
~~~~~~~

- A request object with an ``alg`` that the server does not accept gets an
  ``invalid_request_object`` error instead of ``invalid_request``, per
  RFC 9101 §6.2.
