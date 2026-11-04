Added
~~~~~

- ``IDJAGGrant.resolve_user`` receives the verified claims of the ID-JAG, to
  resolve the user with the ``iss`` and ``sub`` claims.
  ``IDJAGGrant.check_id_jag_permission`` receives them too, in a ``claims``
  argument.

Changed
~~~~~~~

- ``IDJAGGrant`` rejects a ``tenant`` claim that is not a string with
  ``invalid_grant``.

Deprecated
~~~~~~~~~~

- ``IDJAGGrant.authenticate_user``. Implement ``resolve_user`` instead.
- ``IDJAGGrant.check_id_jag_permission`` without a ``claims`` argument.
- ``request.id_jag_claims``. Use the ``claims`` argument of ``resolve_user``
  and ``check_id_jag_permission`` instead.
