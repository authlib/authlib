Breaking changes
~~~~~~~~~~~~~~~~

- The RFC 7591 registration endpoint no longer issues a ``client_secret`` to
  a client that does not use one. This applies to the ``none``,
  ``private_key_jwt``, ``tls_client_auth`` and
  ``self_signed_tls_client_auth`` methods. With the OpenID Connect claims, a
  client still gets a secret when it requests an HMAC algorithm or a
  symmetric encryption algorithm, per OpenID Connect Core §10. Without
  secret, the response and the ``client_info`` of ``save_client`` have
  neither ``client_secret`` nor ``client_secret_expires_at``, per
  :rfc:`7591#section-3.2.1`. The response used to contain
  ``"client_secret": null`` when ``generate_client_secret`` returned
  ``None``.
- ``OAuth2ClientMixin.client_info`` has neither ``client_secret`` nor
  ``client_secret_expires_at`` for a client without secret. The responses of
  the RFC 7592 configuration endpoint change the same way.
- The RFC 7592 configuration endpoint rejects with an
  ``invalid_client_metadata`` error a client without secret that switches to
  metadata that need one, per :rfc:`7592#section-2.2`. Such a client must
  register again.

Added
~~~~~

- ``ClientRegistrationEndpoint.generate_client_info`` and
  ``generate_client_secret`` receive the client metadata as
  ``client_metadata``.
- ``ClientRegistrationEndpoint.needs_client_secret`` tells whether a client
  needs a ``client_secret``. It asks each claims class with a
  ``needs_client_secret`` class method. A client gets a secret when no claims
  class decides. ``ClientConfigurationEndpoint.needs_client_secret`` works the
  same way.

Fixed
~~~~~

- ``OAuth2ClientMixin.check_client_secret`` returns ``False`` for a client
  without secret. It used to raise a ``TypeError``, and the server responded
  with HTTP 500.

Deprecated
~~~~~~~~~~

- ``generate_client_info`` and ``generate_client_secret`` without a
  ``client_metadata`` argument are deprecated. In 1.11, they will always
  receive it.
