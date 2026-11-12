Breaking changes
~~~~~~~~~~~~~~~~

- When the provider metadata has no ``id_token_signing_alg_values_supported``,
  the synchronous OpenID Connect client accepts only ``RS256`` ID tokens, like
  the asynchronous client. For another algorithm, set this metadata in
  ``register``. Both clients refuse unsigned ID tokens, even when the provider
  lists ``none``.

Fixed
~~~~~

- ``parse_id_token`` keeps the issuer check when ``claims_options`` does not
  check ``iss`` itself. It no longer modifies ``claims_options``.
