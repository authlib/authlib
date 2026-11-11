Fixed
~~~~~

- An ID token with an unknown ``kid`` fetches the JWK set of the provider
  again at most once per ``jwks_refresh_interval`` seconds, an attribute of
  the client that is 60 by default. It used to fetch it for every ID token,
  so anyone who could submit ID tokens could make the client send many
  requests to the provider.
