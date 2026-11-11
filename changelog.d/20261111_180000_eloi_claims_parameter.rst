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
- The OpenID Connect grants check the user that the request asks for, with
  ``id_token_hint`` or with the ``sub`` claim of the ``claims`` parameter. An
  ``id_token_hint`` with an invalid signature is refused with
  ``invalid_request``. When the user is another user, they must log in, and
  the request is refused with ``login_required`` if they do not.
  ``get_requested_sub(request)`` returns the requested user.

Deprecated
~~~~~~~~~~

- ``generate_user_info`` methods without a ``claims`` argument are deprecated.
  In 1.11, they will always receive it.
