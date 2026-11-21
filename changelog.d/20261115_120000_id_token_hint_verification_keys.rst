Added
~~~~~

- ``resolve_client_verification_keys`` of the OpenID Connect grants returns the
  keys that verify ``id_token_hint``, including retired keys after a key
  rotation. It defaults to ``resolve_client_private_key``. :issue:`1059`
