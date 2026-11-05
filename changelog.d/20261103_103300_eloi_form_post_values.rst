Fixed
~~~~~

- The ``form_post`` response sends the parameters unchanged. They used to be
  percent-encoded, so the client could receive a modified ``state`` or
  ``error_description``.
- The ``form_post`` response forbids caching with ``Cache-Control: no-store``,
  per OAuth 2.0 Form Post Response Mode §2.
