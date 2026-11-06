Fixed
~~~~~

- OpenID Connect client registration rejects ``request_uris`` that do not use
  https, unless the client registers a ``request_object_signing_alg`` other
  than ``none`` or sets ``require_signed_request_object`` (OpenID Connect
  Dynamic Client Registration §2). ``AUTHLIB_INSECURE_TRANSPORT`` allows http
  for development.
