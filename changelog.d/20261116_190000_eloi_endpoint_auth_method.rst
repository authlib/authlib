Security
~~~~~~~~

- A confidential client can no longer authenticate with its ``client_id``
  only on the revocation, introspection and device authorization endpoints.
  These endpoints accepted the ``none`` method from any client. This affected
  the revocation and introspection endpoints when ``none`` was in their
  ``CLIENT_AUTH_METHODS``, and the device authorization endpoint by default.
  A confidential client whose method is missing from ``CLIENT_AUTH_METHODS``
  now gets an ``invalid_client`` error on these endpoints. Add its method to
  ``CLIENT_AUTH_METHODS``.
