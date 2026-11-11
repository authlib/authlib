Breaking changes
~~~~~~~~~~~~~~~~

- ``JWTBearerClientAssertion.get_audiences()`` must return a non-empty list.
  Client assertions are rejected with ``invalid_client`` when it is empty.
  An empty list used to skip the ``aud`` check.

Fixed
~~~~~

- ``IDJAGGrant`` rejects assertions with ``invalid_grant`` when
  ``get_audiences()`` returns an empty list. An empty list used to skip the
  ``aud`` check.
