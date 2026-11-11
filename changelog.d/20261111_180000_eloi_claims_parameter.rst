Added
~~~~~

- The ``ClaimsParameter`` extension supports the ``claims`` authorization
  request parameter of OpenID Connect Core §5.5. ``generate_user_info``
  receives the requested claims in a new ``claims`` argument, and
  ``UserInfo.filter(scope, claims)`` keeps them. The ``get_claims_request``
  method of the authorization code and the ``get_token_claims_request`` method
  of ``UserInfoEndpoint`` give the parameter to the token endpoint and to the
  UserInfo endpoint. :issue:`758`

Deprecated
~~~~~~~~~~

- ``generate_user_info`` methods without a ``claims`` argument are deprecated.
  In 1.11, they will always receive it.
