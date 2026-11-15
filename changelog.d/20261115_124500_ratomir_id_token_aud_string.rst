Changed
~~~~~~~

- When ``get_client_claims`` returns no ``aud``, the ID token ``aud`` is the
  client ID as a single string instead of a list, so RP-initiated logout can
  find the client from an ``id_token_hint``. :issue:`1054`
