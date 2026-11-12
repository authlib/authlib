Fixed
~~~~~

- ``userinfo()`` raises an ``OAuthError`` when the ``sub`` of the response is
  not the ``sub`` of the ID token returned by ``authorize_access_token``, per
  OpenID Connect Core §5.3.2. :issue:`1043`
