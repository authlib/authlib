Fixed
~~~~~

- ``AsyncOAuth2Client`` no longer refreshes with an outdated refresh token when
  concurrent requests find an expired token. :pr:`963`
