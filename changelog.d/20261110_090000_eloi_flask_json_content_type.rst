Changed
~~~~~~~

- With Flask, the client registration and client configuration endpoints
  read the body as JSON whatever the ``Content-Type``, as with Django. A body
  sent with another ``Content-Type`` used to get an HTTP 415 error page.
