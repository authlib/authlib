Fixed
~~~~~

- :class:`~authlib.oidc.core.OpenIDJWTAuthenticationRequest` can enforce the
  ``request_object_signing_alg`` registered by the client, with the new
  ``get_client_request_object_signing_alg()`` method. Request objects signed
  with another algorithm, including unsigned ones, are rejected.
  :issue:`1021`
