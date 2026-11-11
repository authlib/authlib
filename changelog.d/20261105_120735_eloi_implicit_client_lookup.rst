Fixed
~~~~~

- A client registered with a ``token_endpoint_auth_method`` other than
  ``none`` can use the implicit grant. :issue:`759`

Changed
~~~~~~~

- The implicit grant does not authenticate the client at the authorization
  endpoint anymore. It looks the client up like the authorization code grant,
  with the new ``query_authorization_client`` method of the grant. It no
  longer calls ``authenticate_token_endpoint_client``, so overrides of this
  method and of ``TOKEN_ENDPOINT_AUTH_METHODS`` do not apply to it. The
  ``client_authenticated`` signal is not sent, and a ``client_secret``
  parameter is ignored. To restrict the clients, override
  ``query_authorization_client`` or ``check_response_type``.
