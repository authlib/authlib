Deprecated
~~~~~~~~~~

- The default ``JWTBearerTokenGenerator.get_audiences`` puts the client ID in
  the ``aud`` claim. Per :rfc:`9068#section-3`, ``aud`` is the resource that
  receives the token. Override ``get_audiences`` to return it. In 1.11, the
  default will raise ``NotImplementedError``. :issue:`1004`
