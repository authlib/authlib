Fixed
~~~~~

- An ID token with an unknown ``kid`` fetches the JWK set of the provider at
  most once per ``jwks_refresh_interval``, 60 seconds by default. It used to
  fetch it for every such ID token.
