Breaking changes
~~~~~~~~~~~~~~~~

- Client registration and client configuration updates (:rfc:`7592`) reject a
  ``jwks`` that contains a symmetric key or a private key. Per
  :rfc:`7591#section-2`, ``jwks`` contains the public keys of the client. A
  symmetric key in it could verify HS256 assertions and Request Objects of the
  client. Registered clients with such keys must replace them before they can
  update their metadata.
