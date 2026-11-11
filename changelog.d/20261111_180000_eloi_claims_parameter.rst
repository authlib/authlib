Added
~~~~~

- The ``ClaimsParameter`` extension supports the ``claims`` authorization
  request parameter of OpenID Connect Core §5.5. ``generate_user_info``
  receives the requested claims in a new ``claims`` argument, and
  ``UserInfo.filter(scope, claims)`` keeps them. The ``get_claims_request``
  method of the authorization code and the ``get_token_claims_request`` method
  of ``UserInfoEndpoint`` give the parameter to the token endpoint and to the
  UserInfo endpoint. An essential ``acr`` that the authentication does not
  satisfy is refused with ``access_denied``, or with
  ``unmet_authentication_requirements`` with the new
  ``UnmetAuthenticationRequirements`` extension. :issue:`758`
- ``get_requested_acr_values(request)`` returns the requested ``acr`` values:
  from ``acr_values`` in ``authlib.oauth2.rfc9470``, and also from the
  ``claims`` parameter in ``authlib.oidc.core``.

Deprecated
~~~~~~~~~~

- ``generate_user_info`` methods without a ``claims`` argument are deprecated.
  In 1.11, they will always receive it.
