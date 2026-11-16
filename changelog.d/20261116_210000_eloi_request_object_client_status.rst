Fixed
~~~~~

- With the RFC 9101 extension, an authorization request with a missing or
  unknown ``client_id`` gets a 400 response again, as without the extension.
  It got a 404 since 1.7.0.
