Fixed
~~~~~

- ``IntrospectionToken`` implements ``check_client``, ``is_expired`` and
  ``is_revoked``. They used to raise ``NotImplementedError``. :issue:`508`
