Fixed
~~~~~

- ``AsyncOAuth2Client.ensure_active_token`` re-reads ``self.token`` after the
  refresh lock, matching the sync client. A concurrent refresh is not repeated,
  and the refresh token is taken from the live client token rather than a stale
  argument.
