Added
~~~~~

- The RFC 7523 ``JWTBearerTokenValidator`` accepts an ``audience`` parameter.
  When it is set, the ``aud`` claim must contain it.

Breaking changes
~~~~~~~~~~~~~~~~

- The RFC 7523 ``JWTBearerTokenValidator`` rejects tokens with an ``aud`` claim
  when no ``audience`` is set, per RFC 7519 §4.1.3. The tokens of
  ``JWTBearerTokenGenerator`` have no ``aud`` claim. If your tokens have one,
  pass the identifier of your resource server as ``audience``.
