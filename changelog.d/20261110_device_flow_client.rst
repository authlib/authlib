Added
~~~~~

- Client support for the device authorization grant (:rfc:`8628`), issue
  #1019: ``OAuth2Client.fetch_device_authorization`` sends the device
  authorization request to the ``device_authorization_endpoint`` with client
  authentication, and ``OAuth2Client.poll_device_token`` polls the token
  endpoint, handling the ``authorization_pending`` and ``slow_down``
  (increasing the interval by 5 seconds) responses and raising
  ``expired_token`` and ``access_denied`` errors. Async variants are
  available on ``AsyncOAuth2Client``.
