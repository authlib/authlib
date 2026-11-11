Fixed
~~~~~

- ``create_authorization_response`` returns an ``insecure_transport`` error
  response for a plain HTTP request, instead of raising the error.
  :issue:`973`
