Fixed
~~~~~

- Dynamic client registration refuses client metadata with an unexpected
  type, like a ``scope`` that is not a string or a ``grant_types`` that is not
  a list of strings, with an ``invalid_client_metadata`` error. It used to
  return a server error, or to register the invalid value.
