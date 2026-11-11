Added
~~~~~

- The OpenID Connect client verifies signed UserInfo responses (OpenID
  Connect Core §5.3.2). It checks the signature with the provider JWK set,
  and the ``sub``, ``iss`` and ``aud`` claims. A
  ``userinfo_signed_response_alg`` passed to ``register`` restricts the
  algorithm and refuses unsigned responses. :issue:`941`
