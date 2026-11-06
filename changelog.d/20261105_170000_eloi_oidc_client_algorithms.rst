Breaking changes
~~~~~~~~~~~~~~~~

- When the provider metadata has no ``id_token_signing_alg_values_supported``,
  the synchronous OpenID Connect client accepts only ``RS256`` ID tokens, like
  the asynchronous client. If your provider uses another algorithm, such as
  ``ES256`` or ``HS256``, set this metadata when you register the client. Both
  clients refuse unsigned ID tokens, even when the provider lists ``none``.

Fixed
~~~~~

- ``parse_id_token`` keeps the issuer check when ``claims_options`` does not
  check ``iss`` with a value or a ``validate`` function. It no longer modifies
  ``claims_options``.
