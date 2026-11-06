Breaking changes
~~~~~~~~~~~~~~~~

- OpenID Connect ID tokens are refused when ``aud`` does not contain the
  client ID, even with a matching ``azp`` claim, per OpenID Connect Core
  §3.1.3.7.
