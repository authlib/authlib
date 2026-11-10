Added
~~~~~

- ``get_audiences`` on ``JWTAuthenticationRequest`` and
  ``ClientRegistrationEndpoint`` returns the accepted ``aud`` values of request
  objects and software statements. By default, it returns the ``issuer`` of the
  server metadata.

Breaking changes
~~~~~~~~~~~~~~~~

- JAR request objects and software statements with an ``aud`` claim are
  rejected when ``aud`` contains no value of ``get_audiences``, per
  RFC 7519 §4.1.3. Those without ``aud`` are still accepted. If your clients
  send ``aud``, add ``issuer`` to ``get_server_metadata``, or override
  ``get_audiences``.
