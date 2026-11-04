Added
~~~~~

- ``OpenIDCode``, ``OpenIDImplicitGrant`` and ``OpenIDHybridGrant`` have a
  ``get_request_time(request)`` method. It returns the time the authorization
  request started. With it and ``get_auth_time``, a login after this time
  satisfies ``prompt=login`` and ``max_age=0``, so the user does not have to
  log in again and again.
  ``max_age`` is also measured from this time, and not each time
  ``get_consent_grant`` is called.
- ``request.authorization_key`` is a hash of the authorization request
  parameters. It is the same for all the HTTP requests of one authorization
  request, for instance before and after a login.
