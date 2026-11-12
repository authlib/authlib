Fixed
~~~~~

- A JAR request object with a parameter of the wrong JSON type, such as a
  ``response_type`` list, gets ``invalid_request_object``. It used to raise a
  ``TypeError``. :pr:`970`
- An ID-JAG assertion whose payload is not a JSON object, or whose ``iss`` is
  not a string, gets ``invalid_grant`` instead of an HTTP 500 error.
- A client assertion, a JWT bearer assertion or an ID-JAG assertion with
  deeply nested JSON gets ``invalid_client`` or ``invalid_grant`` instead of
  an HTTP 500 error.
- ``Authorization: Basic`` credentials that are not valid UTF-8 get
  ``invalid_client``. They used to raise a ``UnicodeDecodeError``. :pr:`999`
- A non-ASCII ``client_secret`` gets ``invalid_client`` with the SQLAlchemy
  client mixin. It used to raise a ``TypeError``.
- The client registration and configuration endpoints return
  ``invalid_request`` for a body that is not a JSON object, instead of an HTTP
  500 error.

Changed
~~~~~~~

- With Flask, the client registration and configuration endpoints read the
  body as JSON whatever the ``Content-Type``, as with Django. Another
  ``Content-Type`` used to get an HTTP 415 error page.
