Fixed
~~~~~

- The client registration and client configuration endpoints return an
  ``invalid_request`` error when the request body is not a JSON object. They
  used to return an HTTP 500 error with Django, and an HTTP 500 error or an
  HTML error page with Flask.
