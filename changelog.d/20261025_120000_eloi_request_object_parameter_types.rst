Fixed
~~~~~

- JAR request objects with authorization parameters of the wrong JSON type
  are rejected with an ``invalid_request_object`` error. For instance, a
  ``response_type`` list used to raise a ``TypeError``. The types come from
  the parameters that the grant and the extensions declare, such as
  ``code_challenge``, ``nonce``, ``claims`` or ``response_mode``.
