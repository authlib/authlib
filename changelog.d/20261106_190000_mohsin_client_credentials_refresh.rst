Fixed
~~~~~

- ``fetch_token(grant_type="client_credentials")`` now remembers the grant, so
  an expired token is fetched again. It used to raise ``InvalidTokenError``.
  :issue:`660` :pr:`1009`
