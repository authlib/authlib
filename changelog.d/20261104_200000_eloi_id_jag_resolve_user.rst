Added
~~~~~

- ``IDJAGGrant.resolve_user`` and ``IDJAGGrant.check_id_jag_permission``
  receive the verified claims of the ID-JAG.

Fixed
~~~~~

- ``IDJAGGrant`` rejects a ``tenant`` claim that is not a string with
  ``invalid_grant``.

Deprecated
~~~~~~~~~~

- ``IDJAGGrant.authenticate_user``, ``check_id_jag_permission`` without a
  ``claims`` argument, and ``request.id_jag_claims`` are deprecated. Implement
  ``resolve_user`` and use the ``claims`` argument instead.
