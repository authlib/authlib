Breaking changes
~~~~~~~~~~~~~~~~

- The implicit grant looks the client up with the new
  ``query_authorization_client`` method, like the authorization code grant. It
  no longer authenticates the client, so overrides of
  ``authenticate_token_endpoint_client`` and ``TOKEN_ENDPOINT_AUTH_METHODS``
  do not apply to it, and the ``client_authenticated`` signal is not sent. To
  restrict the clients, override ``query_authorization_client`` or
  ``check_response_type``. :issue:`759`

Fixed
~~~~~

- A client registered with a ``token_endpoint_auth_method`` other than
  ``none`` can use the implicit grant. :issue:`759`
