Added
~~~~~

- ``ClientSecretJWTAuthentication`` and ``PrivateKeyJWTAuthentication`` implement
  the ``client_secret_jwt`` and ``private_key_jwt`` client authentication
  methods. Each one only accepts the clients registered with its method, and
  only its own algorithms: HMAC for ``client_secret_jwt``, asymmetric
  algorithms such as ``PS256`` and ``Ed25519`` for ``private_key_jwt``.

Deprecated
~~~~~~~~~~

- Using or subclassing ``JWTBearerClientAssertion`` is deprecated. It accepts
  both kinds of assertions, so the client chooses the method through the
  ``alg`` of its JWT.

Changed
~~~~~~~

- A JWT client assertion from a client registered with another method gets the
  generic ``invalid_client`` error of the endpoint, instead of an error that
  names ``client_assertion_jwt``.
