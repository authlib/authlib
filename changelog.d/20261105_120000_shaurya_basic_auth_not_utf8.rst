Fixed
~~~~~

- An ``Authorization: Basic`` header whose credentials are not valid UTF-8 is
  ignored like any other malformed credentials, so the client gets an
  ``invalid_client`` error. It used to raise a ``UnicodeDecodeError``.
  :pr:`999`
