Added
~~~~~

- The ``ClaimsParameter`` extension supports the ``claims`` request parameter
  of OpenID Connect Core §5.5. ``generate_user_info`` receives the requested
  claims in a new ``claims`` argument. Implement ``get_claims_request`` on the
  authorization code and ``get_token_claims_request`` on ``UserInfoEndpoint``
  to pass the parameter to the token and UserInfo endpoints. An essential
  ``acr`` that the authentication does not satisfy gets ``access_denied``, or
  ``unmet_authentication_requirements`` with the
  ``UnmetAuthenticationRequirements`` extension. See
  :ref:`flask_oidc_claims_parameter`. :issue:`758`
- The OpenID Connect grants check the user that the request asks for, with
  ``id_token_hint`` or with the ``sub`` of the ``claims`` parameter. Another
  user must log in, or the request gets ``login_required``. An
  ``id_token_hint`` with an invalid signature gets ``invalid_request``.
  :issue:`758`

Deprecated
~~~~~~~~~~

- ``generate_user_info`` methods without a ``claims`` argument are deprecated.
  In 1.11, they will always receive it. :issue:`758`
