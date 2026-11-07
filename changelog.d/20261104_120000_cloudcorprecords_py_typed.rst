Fixed
~~~~~

- Ship a ``py.typed`` marker (PEP 561) in the package so that type checkers
  use Authlib's own source instead of the outdated third-party typeshed
  stubs. Those stubs declared ``AsyncOAuth2Client`` and ``OAuth2Client``
  without their httpx base classes, so checkers reported standard HTTP
  methods such as ``get`` and ``post`` as unknown attributes.
