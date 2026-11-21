Fixed
~~~~~

- ``InsufficientScopeError`` responses include a ``WWW-Authenticate: Bearer``
  header with ``error="insufficient_scope"``, per :rfc:`6750#section-3`.
