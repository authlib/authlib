Fixed
~~~~~

- The OAuth 2 web clients send ``access_token_params`` when they fetch a new
  ``client_credentials`` token on expiry. They used to drop them.
  :issue:`783` :pr:`1026`

Added
~~~~~

- ``OAuth2Session`` and the HTTPX OAuth 2 clients accept
  ``access_token_params``, extra parameters for ``fetch_token`` such as
  ``audience``. They are also sent when a new token is fetched automatically.
