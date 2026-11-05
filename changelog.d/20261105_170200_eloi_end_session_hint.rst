Fixed
~~~~~

- The RP-Initiated Logout endpoint refuses an unsigned ``id_token_hint``, even
  when the server JWKS has an ``oct`` key or ``get_algorithms`` returns
  ``none``. It also refuses a logout token, and a JWT that declares another
  ``typ`` than ``JWT``, like an access token.
