Breaking changes
~~~~~~~~~~~~~~~~

- With ``client_secret_basic``, the client encodes the client ID and secret
  before it sends them, per RFC 6749 §2.3.1. Before, the servers that decode
  them could not read a secret with ``%`` or ``+``, or a client ID with
  ``:``. For a server that does not decode them, pass
  ``encode_client_credentials=False`` to the client or to ``register``, or
  set ``{name}_ENCODE_CLIENT_CREDENTIALS``. :issue:`629`
