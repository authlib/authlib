Fixed
~~~~~

- ``IDJAGGrant`` rejects assertions with a payload that is not a JSON object,
  or with an ``iss`` claim that is not a string, with an ``invalid_grant``
  error. They used to raise an exception and return an HTTP 500 error.
