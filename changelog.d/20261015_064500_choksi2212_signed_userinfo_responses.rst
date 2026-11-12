Added
~~~~~

- The OpenID Connect client verifies signed UserInfo responses, per OpenID
  Connect Core §5.3.2. A ``userinfo_signed_response_alg`` given to
  ``register`` restricts the algorithm and refuses unsigned responses.
  :issue:`941`
