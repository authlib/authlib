Breaking changes
~~~~~~~~~~~~~~~~

- The ``get_audiences`` method of ``JWTBearerClientAssertion`` and of
  ``IDJAGGrant`` must return a non-empty list. An empty list used to skip the
  ``aud`` check. The assertions are now rejected.
