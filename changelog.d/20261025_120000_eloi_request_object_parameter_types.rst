Fixed
~~~~~

- JAR request objects with authorization parameters of the wrong JSON type
  are rejected with an ``invalid_request_object`` error. For instance, a
  ``response_type`` list used to raise a ``TypeError``.
