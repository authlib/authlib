Fixed
~~~~~

- A client whose only grant type is ``implicit`` can use the authorization
  endpoint whatever its ``token_endpoint_auth_method`` is, because it never
  calls the token endpoint. :issue:`759`
