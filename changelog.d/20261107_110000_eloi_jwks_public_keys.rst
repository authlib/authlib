Breaking changes
~~~~~~~~~~~~~~~~

- Client registration and :rfc:`7592` updates reject a ``jwks`` that contains
  a symmetric or private key, per :rfc:`7591#section-2`. Registered clients
  with such keys must replace them before they can update their metadata.
