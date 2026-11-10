Added
~~~~~

- ``JWTAuthenticationRequest.get_audiences`` returns the accepted ``aud``
  values of request objects. By default, it returns the ``issuer`` of the
  server metadata.

Breaking changes
~~~~~~~~~~~~~~~~

- JAR request objects with an ``aud`` claim are rejected when ``aud``
  contains no value of ``get_audiences``, per RFC 7519 §4.1.3. Request objects
  without ``aud`` are still accepted. If your clients send ``aud``, add
  ``issuer`` to ``get_server_metadata``, or override ``get_audiences``.
