Fixed
~~~~~

- Without the RFC 9101 extension, the OpenID Connect grants reject an
  authorization request with a ``request`` or ``request_uri`` parameter, with
  ``request_not_supported`` or ``request_uri_not_supported``. They used to
  ignore the parameter and process the other parameters of the request.
