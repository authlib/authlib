Breaking changes
~~~~~~~~~~~~~~~~

- The client checks the ``issuer`` of the discovery document, per RFC 8414
  §3.3 and OpenID Connect Discovery §4.3. It must be the issuer that
  ``server_metadata_url`` is built from, or the ``issuer`` given to
  ``register``. Otherwise, the client raises ``MismatchingIssuerError``.
  Providers that serve another issuer, such as the Microsoft multi-tenant
  endpoints, need the ``issuer`` parameter, also set with ``{name}_ISSUER`` in
  the Flask and Starlette configuration. The document no longer replaces an
  ``issuer`` given to ``register``. :pr:`1046`
