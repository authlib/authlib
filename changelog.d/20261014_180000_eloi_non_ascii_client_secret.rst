Fixed
~~~~~

- The SQLAlchemy client mixin rejects a non-ASCII ``client_secret`` with an
  ``invalid_client`` error. It used to raise a ``TypeError``.
