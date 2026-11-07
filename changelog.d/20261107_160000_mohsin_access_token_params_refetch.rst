Fixed
~~~~~

- ``access_token_params`` are now sent when a new ``client_credentials`` token
  is fetched automatically. They used to be dropped once the token expired.
  :issue:`783` :pr:`1026`
