Fixed
~~~~~

- ``OpenIDCode`` no longer issues an ID token for a request without ``openid``
  in its ``scope`` parameter. Such a request used to skip the OpenID checks,
  such as ``require_nonce`` and ``prompt``, and still get an ID token when the
  default scope of the client contained ``openid``.
