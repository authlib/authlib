Breaking changes
~~~~~~~~~~~~~~~~

- The client checks the ``issuer`` of the discovery document, per RFC 8414
  §3.3 and OpenID Connect Discovery §4.3. It must be the issuer that
  ``server_metadata_url`` is built from, or the ``issuer`` given to
  ``register``. Otherwise, the client raises ``MismatchingIssuerError``.
  Before, a server could serve the issuer of another provider, with its own
  endpoints and keys. Providers that serve another issuer, such as the
  Microsoft multi-tenant endpoints, need the ``issuer`` parameter. An
  ``issuer`` given to ``register`` is no longer replaced by the issuer of the
  document. It can also be set with ``{name}_ISSUER`` in the Flask and
  Starlette configuration.
