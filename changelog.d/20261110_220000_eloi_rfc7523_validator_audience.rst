Breaking changes
~~~~~~~~~~~~~~~~

- The RFC 7523 ``JWTBearerTokenValidator`` rejects tokens with an ``aud``
  claim, unless its new ``audience`` parameter is set and ``aud`` contains it,
  per RFC 7519 §4.1.3. The tokens of ``JWTBearerTokenGenerator`` have no
  ``aud``. If your tokens have one, pass the identifier of your resource
  server as ``audience``. :pr:`1038`
- JAR request objects and software statements with an ``aud`` claim are
  rejected when ``aud`` contains no value of the new ``get_audiences`` method
  of ``JWTAuthenticationRequest`` and ``ClientRegistrationEndpoint``. By
  default, it returns the ``issuer`` of the server metadata. Objects without
  ``aud`` are still accepted. If your clients send ``aud``, add ``issuer`` to
  ``get_server_metadata``, or override ``get_audiences``. :pr:`1038`
