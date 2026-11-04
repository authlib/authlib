Breaking changes
~~~~~~~~~~~~~~~~

- ``OAuth2Request`` no longer takes a ``body`` parameter, and ``headers`` is
  keyword-only. It no longer has the ``body``, ``data``, ``datalist``,
  ``client_id``, ``response_type``, ``grant_type``, ``redirect_uri`` and
  ``state`` attributes, and no longer inherits from ``OAuth2Payload``. Use
  ``request.payload`` instead. ``JsonRequest.data`` is removed too.
- ``AuthorizationServer.create_authorization_response`` requires the
  ``grant`` returned by ``get_consent_grant``.
- ``JWTBearerClientAssertion`` no longer takes ``token_url``. Override
  ``get_audiences`` instead. Its other parameters are keyword-only.
- ``JWTBearerClientAssertion.resolve_client_public_key`` only receives the
  client.
- ``JWTBearerGrant`` no longer calls ``resolve_client_key``. Implement
  ``resolve_client_public_key`` instead.
- ``ClientRegistrationEndpoint.generate_client_id`` and
  ``generate_client_secret`` receive the request.
- ``IssuerParameter`` can only be registered on the authorization server.
- The OpenID Connect grants no longer call ``get_jwt_config`` and
  ``get_audiences``. Implement ``resolve_client_private_key``,
  ``get_client_claims`` and ``get_client_algorithm`` instead, and set ``aud``
  in ``get_client_claims``. ``OpenIDImplicitGrant.get_audiences`` is removed.
- The OpenID Connect grants and ``OpenIDToken`` require
  ``resolve_client_private_key`` and ``get_client_claims``. Without
  ``get_client_claims``, they used to issue ID tokens without ``iss``.
