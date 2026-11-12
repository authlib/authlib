Changelog
=========

.. meta::
    :description: The full list of changes between each Authlib release.

Here you can see the full list of changes between each Authlib release.

.. scriv-insert-here

.. _changelog-1.10.0b1:

Version 1.10.0b1 — 2026-11-12
-----------------------------

Breaking changes
~~~~~~~~~~~~~~~~

- The RFC 7591 client registration endpoint and the RFC 7592 client
  configuration endpoint respond with HTTP 401 for token errors, per
  :rfc:`7591#section-3.2.2`, :rfc:`7592#section-2.1` and :rfc:`6750#section-3`.
  A request without ``Authorization`` header gets no error code. An invalid
  token gets an ``invalid_token`` error. On the configuration endpoint, a token
  issued to another client and a client that does not exist also get an
  ``invalid_token`` error. Both endpoints used to respond with HTTP 400
  ``access_denied``. The configuration endpoint used to respond with HTTP 401
  ``invalid_client`` when the client did not exist.
- The RFC 7592 client configuration endpoint passes the arguments of
  ``revoke_access_token`` by name. Subclasses must name its parameters
  ``token`` and ``request``.
- A request to a resource protected by ``ResourceProtector`` without
  ``Authorization`` header, or with an unsupported authentication scheme, gets
  an HTTP 401 response with a ``WWW-Authenticate: Bearer`` header and no error
  code, per :rfc:`6750#section-3.1`. The response used to contain a
  ``missing_authorization`` or ``unsupported_token_type`` error. Both cases
  raise ``MissingAuthorizationError``, so a resource with ``optional=True``
  treats an unsupported scheme like a request without token.
- Revocation and introspection endpoints ignore an unknown ``token_type_hint``
  value, per :rfc:`7009#section-2.2` and :rfc:`7662#section-2.1`. They used to
  respond with an ``unsupported_token_type`` error.
- ``UnsupportedTokenTypeError`` responds with HTTP 400, per
  :rfc:`7009#section-2.2.1`. It used to respond with HTTP 401. It is only
  raised when the token type cannot be revoked, like a JWT access token.
  It now inherits from ``OAuth2Error`` instead of ``ForbiddenError``, so it
  no longer takes ``auth_type`` and ``realm`` arguments.
- The :rfc:`9068` revocation and introspection endpoints handle a JWT only if
  its ``typ`` header is ``at+jwt``, per :rfc:`9068#section-2.1`. They no
  longer use the ``token_type_hint``. A JWT access token sent with a
  ``refresh_token`` hint is now handled. Other JWTs, like JWT refresh tokens,
  go to the next endpoint.
- The SQLAlchemy revocation endpoint no longer uses the ``token_type_hint``.
  Revoking an access token keeps the refresh token active, with or without a
  hint. Revoking a refresh token also revokes the access token, per
  :rfc:`7009#section-2.1`.
- ``JWTBearerClientAssertion.get_audiences()`` must return a non-empty list.
  Client assertions are rejected with ``invalid_client`` when it is empty.
  An empty list used to skip the ``aud`` check.
- Hooks run around the most derived override of a method. An ``after`` hook
  used to run when the parent method returned inside ``super()``. It now runs
  when the override returns, and it gets the result of the override. Hooks also
  run when the override does not call ``super()``. For example, ``OpenIDCode``
  now adds the ``id_token`` when ``create_token_response`` is overridden.
- Methods of a mixin that is not ``Hookable`` no longer run hooks, even with
  ``hooked``. Registering a hook on them raises a ``TypeError``. Make the
  mixin inherit from ``Hookable``. A mixin method that overrides a method of a
  ``Hookable`` class still runs hooks.
- A hook name that matches a static method, a class method or a property
  raises a ``TypeError``.
- The first two parameters of ``register_hook`` are positional-only.
  ``register_hook(hook_type=..., hook=...)`` raises a ``TypeError``.
- ``hooked`` raises a ``TypeError`` when it gets custom hook names.
- The OpenID Connect implicit and hybrid flows only accept the ``fragment``
  and ``form_post`` response modes. Other values, ``query`` included, get an
  ``invalid_request`` error in the fragment, before the user consent. Per
  OAuth 2.0 Multiple Response Type Encoding Practices §3 and §5, these
  responses must not be sent in the query string. An unknown value used to
  raise a ``ValueError`` after the user consent.
- ``OAuth2AuthorizationCodeMixin`` has an ``issued_at`` column, and
  ``is_expired`` uses it. The ``auth_time`` column is now the time of the user
  authentication, and it is nullable. In your migration, add the
  ``issued_at`` column, copy the ``auth_time`` values into it, and make
  ``auth_time`` nullable.
- Stop supporting Python 3.10. Authlib supports Python 3.11 to 3.15.
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
- ``IssuerParameter.add_issuer_parameter`` receives an
  ``AuthorizationResponse``, and adds ``iss`` to its ``params``. It used to
  receive the framework response and change its ``Location`` header.
  ``IssuerParameter`` no longer adds ``iss`` to the responses of custom grants
  that return a tuple or a redirection. Return an ``AuthorizationResponse``
  instead.
- Per :rfc:`9700#section-4.11.2`, an anonymous user is not redirected to the
  client with an error. When their request has an error, ``get_consent_grant``
  returns the grant with the ``"login"`` interaction. After the login, it
  raises the error, and the user is redirected. ``create_authorization_response``
  returns the error of such a grant without redirection, and never issues a
  code. An anonymous user gets ``unsupported_response_type`` without
  redirection. With the OpenID Connect ``prompt=none``, errors are redirected
  at once. If you do not pass the user to ``get_consent_grant``, all the users
  are anonymous for Authlib. Set ``server.defer_anonymous_errors = False`` to
  redirect all the errors at once, as before.
- Without the ``MultipleResponseTypes`` extension, when the user denies an
  OpenID Connect implicit or hybrid request with ``response_mode=form_post``,
  the ``access_denied`` error is sent in the fragment, like the other errors.
- When the provider metadata has no ``id_token_signing_alg_values_supported``,
  the synchronous OpenID Connect client accepts only ``RS256`` ID tokens, like
  the asynchronous client. If your provider uses another algorithm, such as
  ``ES256`` or ``HS256``, set this metadata when you register the client. Both
  clients refuse unsigned ID tokens, even when the provider lists ``none``.
- OpenID Connect ID tokens are refused when ``aud`` does not contain the
  client ID, even with a matching ``azp`` claim, per OpenID Connect Core
  §3.1.3.7.
- ``JWTBearerTokenValidator`` refuses a JWT access token without a ``typ``
  header, per :rfc:`9068#section-4`. It used to accept it, so another JWT
  without ``typ`` signed by the same issuer, like the ID tokens of some
  providers, could be used as an access token. ``JWTBearerTokenGenerator``
  always sets ``typ`` to ``at+jwt``.
- The OAuth 2 clients raise a ``ValueError`` when ``code_challenge_method`` is
  not ``S256`` or ``plain``. They used to skip PKCE for other values.
- The OAuth 2 and OpenID Connect authorization server redirects with a 303
  status code instead of 302, per :rfc:`9700#section-4.12`. This covers
  authorization responses, errors sent to the redirect URI, and the
  RP-Initiated Logout redirection. With 303, the browser always uses GET after
  a POST, such as a consent form. With 302, this choice was left to the
  browser.
- ``authlib.jose`` rejects JWS and JWE segments that are not canonical
  base64url, such as a signature with padding, extra characters, or a trailing
  newline. A token now has a single serialization, like in joserfc. Strip the
  token before decoding it if it comes from a file.
- Client registration and client configuration updates (:rfc:`7592`) reject a
  ``jwks`` that contains a symmetric key or a private key. Per
  :rfc:`7591#section-2`, ``jwks`` contains the public keys of the client. A
  symmetric key in it could verify HS256 assertions and Request Objects of the
  client. Registered clients with such keys must replace them before they can
  update their metadata.
- The RFC 7523 ``JWTBearerTokenValidator`` rejects tokens with an ``aud`` claim
  when no ``audience`` is set, per RFC 7519 §4.1.3. The tokens of
  ``JWTBearerTokenGenerator`` have no ``aud`` claim. If your tokens have one,
  pass the identifier of your resource server as ``audience``.
- JAR request objects and software statements with an ``aud`` claim are
  rejected when ``aud`` contains no value of ``get_audiences``, per
  RFC 7519 §4.1.3. Those without ``aud`` are still accepted. If your clients
  send ``aud``, add ``issuer`` to ``get_server_metadata``, or override
  ``get_audiences``.
- The client checks the ``issuer`` of the discovery document, per RFC 8414
  §3.3 and OpenID Connect Discovery §4.3. It must be the issuer that
  ``server_metadata_url`` is built from, or the ``issuer`` given to
  ``register``. Otherwise, the client raises ``MismatchingIssuerError``.
  Before, a server could serve the issuer of another provider, with its own
  endpoints and keys. Providers that serve another issuer, such as the
  Microsoft multi-tenant endpoints, need the ``issuer`` parameter. An
  ``issuer`` given to ``register`` is no longer replaced by the issuer of the
  document. It can also be set with ``{name}_ISSUER`` in the Flask and
  Starlette configuration.

Added
~~~~~

- Automatically fetch initial OAuth2 access tokens for the
  ``client_credentials`` grant in Requests and synchronous
  and asynchronous HTTPX clients when a token endpoint is
  configured (issue #531, PR #946).
- Support Python 3.15.
- ``ClientSecretJWT`` and ``PrivateKeyJWT`` accept an ``expires_in`` parameter
  for the lifetime of the client assertion, which used to be hardcoded to
  3600 seconds. Identity providers that cap assertion lifetimes, such as
  Auth0's 5-minute limit for ``private_key_jwt``, can now be used without a
  custom client authentication subclass. :issue:`857`
- The OpenID Connect client verifies signed UserInfo responses (OpenID
  Connect Core §5.3.2). It checks the signature with the provider JWK set,
  and the ``sub``, ``iss`` and ``aud`` claims. A
  ``userinfo_signed_response_alg`` passed to ``register`` restricts the
  algorithm and refuses unsigned responses. :issue:`941`
- The web client guide documents passing ``leeway`` and other ``OAuth2Session`` options through ``client_kwargs``.
  :issue:`687` :pr:`960`
- The OpenID Connect client guide explains how to read custom claims.
  :issue:`621` :pr:`961`
- The Flask resource server guide covers JWT access tokens and accepting several issuers.
  :issue:`671` :pr:`962`
- Add support for `OpenID Connect Back-Channel Logout 1.0
  <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_.
  See :ref:`specs/backchannel` for details. :PR:`874`
- Add support for :rfc:`9728` OAuth 2.0 Protected Resource Metadata for
  resource servers and authorization servers. :pr:`790`
- Add the ``FormEncodedBodyToken`` resource protector extension. It accepts
  the access token in a form-encoded request body, per :rfc:`6750#section-2.2`.
  :issue:`756` :pr:`905`
- Hooks can run before, after or instead of any method defined in a
  ``Hookable`` class, such as a grant, an authorization server or a resource
  protector. Register a hook with a
  reference to the method, such as
  ``grant.register_hook(hook, after=AuthorizationCodeGrant.validate_token_request)``.
  Hook names such as ``"after_validate_token_request"`` still work.
- Support ``prompt=create`` and ``prompt_values_supported`` from Initiating
  User Registration via OpenID Connect 1.0, with the ``PromptValues``
  authorization server extension. Its ``get_server_metadata`` returns the
  supported ``prompt`` values. The other values get an HTTP 400
  ``invalid_request`` error. When the list contains ``create``, it comes
  first in ``grant.interactions`` for an anonymous user. :issue:`735`
  :PR:`907`
- ``authlib.oauth2.rfc6749.normalize_response_type`` sorts the values of a
  ``response_type``, so two response types can be compared whatever the order
  of their values.
- Grants and endpoints return an ``OAuth2Response``, a ``JsonResponse`` or a
  ``RedirectResponse``. A ``before`` hook on
  ``AuthorizationServer.encode_response`` can change any response of the
  authorization server, errors included.
- Authorization grants return an ``AuthorizationResponse``. It holds the
  parameters sent to the client, and the authorization server encodes them
  according to the response mode. In ``form_post`` mode, the OpenID Connect
  implicit and hybrid grants do not use it yet.
- ``authlib.oauth2.multiple_response_types.MultipleResponseTypes`` implements
  OAuth 2.0 Multiple Response Type Encoding Practices. Clients choose the
  response mode of any authorization grant with the ``response_mode``
  parameter, and errors use it too. The server accepts the modes of its
  ``response_modes_supported`` metadata, and never sends access tokens or ID
  Tokens in the query.
- ``authlib.oauth2.form_post.FormPost`` implements OAuth 2.0 Form Post
  Response Mode for any authorization grant. Pass it to the
  ``MultipleResponseTypes`` extension. A grant can use it by default with
  ``RESPONSE_MODE = "form_post"``.
- The OpenID Connect grants enforce the ``max_age`` parameter and the
  ``default_max_age`` client metadata, with the login time of the
  authorization session. When the last login is too old, ``"login"`` is added
  to ``grant.interactions``, and with ``prompt=none`` the server returns
  ``login_required``. ``max_age=0`` works like ``prompt=login``, and an
  invalid ``max_age`` gives an ``invalid_request`` error.
- The ``StepUpAuthentication`` extension of RFC 9470 enforces ``max_age`` for
  the requests without the ``openid`` scope too. The ``acr_values`` parameter
  and the rest of RFC 9470 are not supported yet.
- The ``framework_request`` property of the Flask and Django OAuth 2.0
  requests gives the request of the framework.
- ``OAuth2ClientMixin`` has a ``default_max_age`` property.
- Grants and grant extensions declare the authorization request parameters
  they introduce, with ``register_authorization_parameters``. Server extensions
  use ``AuthorizationServer.register_authorization_parameters``.
- ``AuthorizationServer.authorization_parameters`` gives the RFC 6749
  parameters and those of the server extensions, with their JSON types.
- ``grant.interactions`` lists the interactions the user must go through
  before the authorization response, in this order: ``"create"``,
  ``"login"``, ``"select_account"`` and ``"consent"``. ``grant.prompt`` is the
  first of them.
- ``AuthorizationSessionMixin`` gives Authlib the facts about the session of
  the user. Pass it to ``get_consent_grant(session=...)`` instead of the user.
  It gives the time the authorization request started, and the time of the
  last login, consent and account selection. An interaction that the client
  asks for, such as ``prompt=login`` or ``prompt=consent``, is done when it
  happened after the request started, so the user is not asked again and
  again. A login also counts as an account selection. ``is_consent_needed``
  tells if the user must give their consent, and ``end_request`` is called
  when the authorization request ends. ``authlib.oauth2.AuthorizationSession``
  keeps the start time of the requests in the session of the web framework.
  The session is only written when the user must go through an interaction,
  or when a rule needs the start time. With the OpenID Connect ``prompt=none``,
  it is not written.
- With ``prompt=none``, the OpenID Connect grants return ``consent_required``
  or ``account_selection_required`` when the authorization session needs the
  consent or the account selection of the user. :issue:`740`
- ``request.authorization_key`` is a hash of the authorization request
  parameters. It is the same for all the HTTP requests of one authorization
  request, for instance before and after a login.
- ``IDJAGGrant.resolve_user`` receives the verified claims of the ID-JAG, to
  resolve the user with the ``iss`` and ``sub`` claims.
  ``IDJAGGrant.check_id_jag_permission`` receives them too, in a ``claims``
  argument.
- ``AuthorizationSessionMixin.can_redirect_error`` tells if an error can be
  sent to the redirect URI of the client. Per :rfc:`9700#section-4.11.2`,
  return false for the redirect URIs you do not trust. The error is then
  returned without redirection. It also applies to ``access_denied``.
- ``grant.silent`` is true when the request must be done without any user
  interaction, such as with the OpenID Connect ``prompt=none``.
- ``NoneResponseTypeGrant`` supports ``response_type=none``, from OAuth 2.0
  Multiple Response Type Encoding Practices. The client receives ``state``,
  and no code or token.
- ``OAuth.remove_client(name)`` removes a registered remote application
  (issue #583).
- ``AssertionClient``, ``AssertionSession`` and the HTTPX assertion clients
  accept ``access_token_params``, extra parameters for the token request such
  as ``resource``.
- The requests and httpx OAuth 1 and OAuth 2 clients accept URL objects, such
  as ``httpx.URL``, for the endpoints, the redirect URI and the authorization
  response. :issue:`931`
- ``OAuth2Session`` and the HTTPX OAuth 2 clients accept
  ``access_token_params``, extra parameters for ``fetch_token`` such as
  ``audience``. They are also sent when a new token is fetched automatically.
- ``CodeChallenge.is_code_challenge_required`` tells whether a client must use
  PKCE. Override it to require PKCE for all clients, as recommended by
  :rfc:`RFC 9700 §2.1.1 <9700#section-2.1.1>`. The codes issued without
  ``code_challenge`` are then rejected at the token endpoint. :issue:`1012`
- The requests clients accept ``headers``, like the httpx clients. These
  headers are sent with every request of the session. With the web framework
  integrations, ``client_kwargs={"headers": ...}`` also sends them with the
  ``server_metadata_url`` and ``jwks_uri`` requests. Before, a ``headers``
  value given to the requests clients was ignored. :issue:`633`
- The RFC 7523 ``JWTBearerTokenValidator`` accepts an ``audience`` parameter.
  When it is set, the ``aud`` claim must contain it.
- ``get_audiences`` on ``JWTAuthenticationRequest`` and
  ``ClientRegistrationEndpoint`` returns the accepted ``aud`` values of request
  objects and software statements. By default, it returns the ``issuer`` of the
  server metadata.
- The authorization session gives the ``acr`` and ``amr`` of the
  authentication with ``get_acr(request)`` and ``get_amr()``, from the
  ``authlib.oauth2.rfc9470.AuthorizationSessionMixin``. The OpenID Connect
  grants put them in the ID token, now also in the implicit and hybrid flows.
  For the code flow, they set ``request.acr`` and ``request.amr`` for
  ``save_authorization_code``. The documentation explains how to answer the
  ``acr_values`` parameter. :issue:`744`
- ``UnmetAuthenticationRequirementsError``, from the OpenID Connect Core Error
  Code unmet_authentication_requirements specification, refuses a request whose
  authentication requirements cannot be met.
- ``AuthorizationCodeGrant.revoke_authorization_code_tokens(code, client)`` is
  called when a code is not found, before the request is denied. Implement it
  to revoke the tokens issued with a reused code, per RFC 6749 §4.1.2. The
  documentation shows how to link the tokens to their code. :issue:`757`
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

Changed
~~~~~~~

- When the request asks for several interactions, ``grant.prompt`` follows the
  new order. For instance, with ``prompt=consent select_account``, it is
  ``"select_account"`` instead of ``"consent"``.
- ``get_consent_grant`` calls the new ``validate_interactions`` method of the
  grant after ``validate_consent_request``. With ``prompt=none``, the
  ``consent_required`` and ``account_selection_required`` errors are raised
  there. If you override ``get_consent_grant``, call it too.
- ``IDJAGGrant`` rejects a ``tenant`` claim that is not a string with
  ``invalid_grant``.
- ``grant.interactions`` contains ``"login"`` when the user is not logged in,
  also without OpenID Connect.
- The implicit grant does not authenticate the client at the authorization
  endpoint anymore. It looks the client up like the authorization code grant,
  with the new ``query_authorization_client`` method of the grant. It no
  longer calls ``authenticate_token_endpoint_client``, so overrides of this
  method and of ``TOKEN_ENDPOINT_AUTH_METHODS`` do not apply to it. The
  ``client_authenticated`` signal is not sent, and a ``client_secret``
  parameter is ignored. To restrict the clients, override
  ``query_authorization_client`` or ``check_response_type``.
- The OIDC userinfo endpoint reads the token scope with ``get_scope()``.
  Custom token classes used with this endpoint must implement it.
- With Flask, the client registration and client configuration endpoints
  read the body as JSON whatever the ``Content-Type``, as with Django. A body
  sent with another ``Content-Type`` used to get an HTTP 415 error page.

Deprecated
~~~~~~~~~~

- ``authlib.oauth2.rfc6749.hooks.hooked`` is deprecated and does nothing.
  Methods of a ``Hookable`` class run their hooks without it. It will be
  removed in version 1.11.
- Returning a ``(status_code, body, headers)`` tuple from a grant or an
  endpoint is deprecated. Return an ``OAuth2Response`` instead.
- Using an ``OAuth2Response`` as a ``(status_code, body, headers)`` tuple is
  deprecated. This happens in an override that unpacks
  ``super().create_token_response()`` or
  ``super().create_authorization_response()``, or in a hook that reads
  ``result[1]``. Use the ``status_code``, ``body`` and ``headers``
  attributes. It will stop working in version 1.11.
- Using ``response_mode`` with the OpenID Connect implicit and hybrid grants
  without the ``MultipleResponseTypes`` extension is deprecated. Register it
  with ``server.register_extension(MultipleResponseTypes())``. It will stop
  working in version 1.11.
- ``DEFAULT_RESPONSE_MODE`` of the OpenID Connect implicit and hybrid grants
  is deprecated. Use ``RESPONSE_MODE`` instead. It will stop working in
  version 1.11.
- ``authlib.oidc.core.grants.util.create_response_mode_response`` is
  deprecated. Return an ``AuthorizationResponse`` instead. It will be removed
  in version 1.11.
- Using the OpenID Connect grants without an authorization session is
  deprecated. Until then, ``max_age`` is only enforced when it is ``0``, and
  ``auth_time`` is the current time. It will be required in version 1.11.
- Setting ``grant.prompt`` is deprecated. It only changes the value that
  ``grant.prompt`` returns. Read ``grant.interactions`` instead.
- ``IDJAGGrant.authenticate_user``. Implement ``resolve_user`` instead.
- ``IDJAGGrant.check_id_jag_permission`` without a ``claims`` argument.
- ``request.id_jag_claims``. Use the ``claims`` argument of ``resolve_user``
  and ``check_id_jag_permission`` instead.
- The default ``JWTBearerTokenGenerator.get_audiences`` puts the client ID in
  the ``aud`` claim. Per :rfc:`9068#section-3`, ``aud`` holds the identifier of
  the resource that receives the token. Override ``get_audiences`` to return
  it. In 1.11, the default implementation will raise ``NotImplementedError``.
  :issue:`1004`
- The ``required`` parameter of ``CodeChallenge`` is deprecated. Override
  ``is_code_challenge_required`` instead. It will stop working in version
  1.11.
- Access token generators receive ``expires_in``, the lifetime of the token.
  A self-contained token can use it to set its expiration time. Generators
  without this parameter still work, with a warning. In 1.11, they will
  always receive it. Add an ``expires_in`` parameter to the function of
  ``OAUTH2_ACCESS_TOKEN_GENERATOR`` (Flask) or ``access_token_generator``
  (Django), and to ``access_token_generator`` overrides in
  ``JWTBearerTokenGenerator`` subclasses.
- ``authlib.oauth2.rfc7523.JWTBearerTokenGenerator`` and
  ``authlib.oauth2.rfc7523.JWTBearerTokenValidator`` are deprecated. They use a
  custom JWT access token format, which :rfc:`9068` now standardizes. Use the
  classes of the same name in ``authlib.oauth2.rfc9068`` instead. The generator
  will be removed in 1.11, and the validator in 2.0. :issue:`846`
- ``generate_user_info`` methods without a ``claims`` argument are deprecated.
  In 1.11, they will always receive it.

Fixed
~~~~~

- The SQLAlchemy client mixin rejects a non-ASCII ``client_secret`` with an
  ``invalid_client`` error. It used to raise a ``TypeError``.
- The RFC 7592 client configuration endpoint passes the token and the request
  to ``revoke_access_token`` in the documented ``(token, request)`` order. It
  used to swap them. Subclasses that use the swapped ``(request, token)``
  signature keep working.
- Revocation and introspection endpoints search all token types when the
  token is not found with the ``token_type_hint``, per :rfc:`7009#section-2.1`
  and :rfc:`7662#section-2.1`. A refresh token sent with an ``access_token``
  hint used to be ignored, so it was not revoked. Custom
  ``revoke_token`` methods must not trust the hint to know which token was
  presented.
- ``AsyncOAuth2Client`` no longer refreshes with an outdated refresh token when
  concurrent requests find an expired token. :pr:`963`
- ``AssertionSession``, ``ClientSecretJWT`` and ``PrivateKeyJWT`` send a new
  ``jti`` with every assertion when they are given ``claims``. The generated
  ``jti`` used to be written into the ``claims`` dict and sent again on every
  later request, so identity providers that check ``jti`` rejected the second
  token request as a replay.
- JAR request objects with authorization parameters of the wrong JSON type
  are rejected with an ``invalid_request_object`` error. For instance, a
  ``response_type`` list used to raise a ``TypeError``. The types come from
  the parameters that the grant and the extensions declare, such as
  ``code_challenge``, ``nonce``, ``claims`` or ``response_mode``.
- ``AuthorizationServer.create_token_response`` and
  ``create_endpoint_response`` return an ``insecure_transport`` error response
  for a plain HTTP request, instead of raising ``InsecureTransportError``.
- ``IDJAGGrant`` rejects assertions with a payload that is not a JSON object,
  or with an ``iss`` claim that is not a string, with an ``invalid_grant``
  error. They used to raise an exception and return an HTTP 500 error.
- ``IDJAGGrant`` rejects assertions with ``invalid_grant`` when
  ``get_audiences()`` returns an empty list. An empty list used to skip the
  ``aud`` check.
- Hooks run in the order they are registered. The order used to be random.
- The ``httpx`` client integrations initialize their transport base with
  ``super()``, so ``OAuth2Client``, ``AsyncOAuth2Client``,
  ``OAuth1Client``, ``AsyncOAuth1Client``, ``AssertionClient`` and
  ``AsyncAssertionClient`` no longer raise ``TypeError`` when an
  instrumentation library such as ``aws-xray-sdk`` or
  ``opentelemetry-instrumentation-httpx`` has patched the httpx client
  classes.
  :issue:`557` :pr:`953`
- When the user denies the request, the OpenID Connect implicit and hybrid
  flows return the ``state`` parameter.
- The ``form_post`` response sends the parameters unchanged. They used to be
  percent-encoded, so the client could receive a modified ``state`` or
  ``error_description``.
- The ``form_post`` response forbids caching with ``Cache-Control: no-store``,
  per OAuth 2.0 Form Post Response Mode §2.
- OpenID Connect dynamic client registration rejects the ``none``
  ``id_token_signed_response_alg`` when the ``response_types`` return an ID
  Token from the authorization endpoint, per OpenID Connect Dynamic Client
  Registration §2. The check used to read a ``response_type`` metadata that
  does not exist, so it never applied.
- The order of the values in a ``response_type`` does not matter anymore, per
  RFC 6749 §3.1.1. This applies to the ``RESPONSE_TYPES`` of the grants, to
  the ``response_types`` of the SQLAlchemy client mixin, and to
  ``get_claim_cls_by_response_type``.
- The ``auth_time`` claim of the ID token is the login time of the
  authorization session. It used to be the time the ID token or the
  authorization code was created. In the code and hybrid flows, store
  ``request.auth_time`` in ``save_authorization_code``. When the time is
  unknown, the ID token has no ``auth_time``.
- An authorization request that repeats a parameter of an extension, such as
  ``nonce`` or ``code_challenge``, gets an ``invalid_request`` error
  (RFC 6749 §3.1). Only the RFC 6749 parameters used to be checked.
- An authorization request that repeats an RFC 6749 parameter or a parameter
  of a server extension, such as ``client_id``, ``request`` or
  ``request_uri``, gets an ``invalid_request`` error before the grant is
  chosen. With JAR, the request object is not fetched or decoded.
- With a ``cache``, the Flask, Django and Starlette clients refuse an unknown
  ``state`` with ``MismatchingStateError``. They no longer pass it to the
  cache, whose backend could reject it with an unhandled error.
- ``IssuerParameter`` adds ``iss`` to the fragment of fragment responses and
  to the form of ``form_post`` responses. It used to add it to the query of
  fragment responses, and to omit it in ``form_post`` responses and in the
  errors of the consent page.
- With a request object (:rfc:`9101`), the errors of
  ``create_authorization_response``, such as ``access_denied``, contain the
  ``state`` of the request object.
- An ``Authorization: Basic`` header whose credentials are not valid UTF-8 is
  ignored like any other malformed credentials, so the client gets an
  ``invalid_client`` error. It used to raise a ``UnicodeDecodeError``.
  :pr:`999`
- A client registered with a ``token_endpoint_auth_method`` other than
  ``none`` can use the implicit grant. :issue:`759`
- ``create_authorization_response`` returns an ``insecure_transport`` error
  response for a plain HTTP request, instead of raising the error.
  :issue:`973`
- The OIDC userinfo endpoint accepts :rfc:`9068` JWT access tokens.
  Override the new ``get_token_client`` and ``get_token_user`` methods of
  ``UserInfoEndpoint`` to load the client and the user from the token claims.
  If one of them returns ``None``, the endpoint returns an ``invalid_token``
  error instead of a server error. :issue:`831`
- ``parse_id_token`` keeps the issuer check when ``claims_options`` does not
  check ``iss`` with a value or a ``validate`` function. It no longer modifies
  ``claims_options``.
- The RP-Initiated Logout endpoint refuses an unsigned ``id_token_hint``, even
  when the server JWKS has an ``oct`` key or ``get_algorithms`` returns
  ``none``. It also refuses a logout token, and a JWT that declares another
  ``typ`` than ``JWT``, like an access token.
- Dynamic client registration refuses client metadata with an unexpected
  type, like a ``scope`` that is not a string or a ``default_acr_values`` that
  is not a list of strings, with an ``invalid_client_metadata`` error. It used
  to return a server error, or to register the invalid value. This covers the
  RFC 7591, OpenID Connect, RP-Initiated Logout and Back-Channel Logout
  metadata. A ``null`` value is ignored, so the default value applies. An
  ``http`` post logout redirect URI for a public client also gets
  ``invalid_client_metadata``, instead of a ``ValueError``.
- Dynamic client registration refuses an expired software statement, or one
  whose ``nbf`` or ``iat`` is in the future, with an
  ``invalid_software_statement`` error. ``software_statement_leeway`` allows
  60 seconds of clock skew by default.
- The client authentication debug logs quote the ``client_id``, so a
  ``client_id`` with a line feed can no longer add fake lines to the logs.
- The size limits of ``authlib.jose`` raise ``ExceededSizeError``, a
  ``JoseError``, so an application that catches ``JoseError`` refuses a too
  long token instead of failing. It is also a ``ValueError``, as before.
- An ID token with an unknown ``kid`` fetches the JWK set of the provider
  again at most once per ``jwks_refresh_interval`` seconds, an attribute of
  the client that is 60 by default. It used to fetch it for every ID token,
  so anyone who could submit ID tokens could make the client send many
  requests to the provider.
- The Requests and HTTPX OAuth 2 clients send all the values of the ``resource``
  (:rfc:`8707`) and ``audience`` (:rfc:`8693`) parameters. They used to send
  only the last value in token, refresh, revocation and introspection requests.
  ``fetch_token`` and ``refresh_token`` also accept a list for these
  parameters. A list used to raise a ``TypeError``.
- When PKCE is required, the authorization endpoint rejects a public client
  without ``code_challenge``, per :rfc:`7636#section-4.4.1`. The error used to
  come only at the token endpoint, after the login and the consent.
- The authorization endpoint rejects a request without
  ``code_challenge_method`` when ``plain`` is not in
  ``SUPPORTED_CODE_CHALLENGE_METHOD``. Per :rfc:`7636#section-4.3`, a missing
  method means ``plain``. Such requests used to be accepted with ``plain``.
- The OAuth 2 clients support the ``plain`` PKCE method (issue #709). They
  also add the PKCE challenge for a ``response_type`` that contains ``code``,
  such as ``code id_token``. In both cases, the clients used to send a
  ``code_verifier`` without ``code_challenge``, and the server rejected the
  request.
- Registering a remote application with a name that is already registered
  replaces it. It used to return the first client.
- Registering a remote application no longer changes
  ``client_cls.OAUTH_APP_CONFIG`` or the dicts given to ``register``, such as
  ``client_kwargs``.
- ``fetch_token(grant_type="client_credentials")`` now remembers the grant, so
  an expired token is fetched again. It used to raise ``InvalidTokenError``.
  :issue:`660` :pr:`1009`
- ``PrivateKeyJWT`` accepts an EC or OKP private key as a PEM string or a JWK
  dict. The key type follows ``alg``. It used to import every key as an RSA
  key.
- JWT assertions signed by authlib carry the ``kid`` of the key, unless the
  header sets one (OpenID Connect Core §10.1). This covers ``PrivateKeyJWT``,
  ``ClientSecretJWT``, JWT bearer grants and ID-JAG. Servers can then find the
  right key when the signer has several keys.
- Signing a JWT assertion no longer adds ``alg`` to the ``headers`` dict given
  by the caller.
- The Flask, Django and Starlette clients raise an ``OAuthError`` for an error
  response sent with ``response_mode=form_post``. They used to ignore the
  error and try to fetch a token without a code.
- The ``OAuthError`` raised for an authorization error response carries its
  ``error_uri`` as ``uri``.
- OpenID Connect client registration rejects ``request_uris`` that do not use
  https, unless the client registers a ``request_object_signing_alg`` other
  than ``none`` or sets ``require_signed_request_object`` (OpenID Connect
  Dynamic Client Registration §2). ``AUTHLIB_INSECURE_TRANSPORT`` allows http
  for development.
- The RFC 7591 and RFC 7592 endpoints do not check if a token is expired or
  revoked, so ``authenticate_token`` must return ``None`` for such tokens. The
  docstrings and the documentation examples now say so.
- The OAuth 2 web clients send ``access_token_params`` when they fetch a new
  ``client_credentials`` token on expiry. They used to drop them.
  :issue:`783` :pr:`1026`
- The OAuth 1 temporary credentials response sets ``oauth_callback_confirmed``
  to ``true`` instead of ``True``, per RFC 5849 §2.1.
- ``JsonWebEncryption`` rejects a JWE whose ``crit`` header lists a header
  parameter it does not understand, or whose ``crit`` header is not in the
  protected header, as ``JsonWebSignature`` already does. Add the private
  header parameters listed in ``crit`` to ``private_headers``.
- Client assertions, JWT bearer assertions and ID-JAG assertions with deeply
  nested JSON return an ``invalid_client`` or ``invalid_grant`` error instead
  of an HTTP 500 error. ``OAuth1Client`` raises a ``ValueError`` for such
  token responses.
- The client registration and client configuration endpoints return an
  ``invalid_request`` error when the request body is not a JSON object. They
  used to return an HTTP 500 error with Django, and an HTTP 500 error or an
  HTML error page with Flask.
- The OAuth 2 web clients no longer pass the ``server_metadata_url`` document
  to the requests or httpx client. Only its ``token_endpoint`` is used. A key
  such as ``hooks``, ``verify``, ``client_id`` or ``scope`` in this document
  used to change the client settings, or to break every request.
  :issue:`1017`
- The async OAuth 2 web clients use the ``redirect_uri`` of ``client_kwargs``
  when ``create_authorization_url`` gets none. They used to send no
  ``redirect_uri``.
- OAuth 1.0a base string URI normalization now excludes the default port
  (80 for HTTP, 443 for HTTPS) for IPv6 hosts, as required by
  :rfc:`5849#section-3.4.1.2`.
- ``JWTBearerTokenGenerator`` uses the ``expires_in`` given to ``generate``
  or ``generate_token`` for the ``exp`` claim. Before, the JWT kept the
  default lifetime while the response announced the given one.
- The hybrid flow redirects its errors in the fragment instead of the query,
  for a missing ``nonce``, an unsupported scope and an unauthorized
  ``response_type``. ``exists_nonce`` is no longer called one more time at
  each validation of the request.
- ``userinfo()`` raises an ``OAuthError`` when the ``sub`` of the response is
  not the ``sub`` of the ID token returned by ``authorize_access_token``, per
  OpenID Connect Core §5.3.2. :issue:`1043`

.. _changelog-1.9.5:

Version 1.9.5 — 2026-11-05
--------------------------

Security
~~~~~~~~

- ``authlib.jose`` refuses as an HMAC secret every OpenSSH public key or
  certificate that it can load as an RSA, EC or OKP key. It used to accept a
  key with a tab after the key type, and certificates. These keys verify
  ``RS256`` and ``EdDSA`` tokens, so anyone who knew the public key could
  forge an ``HS256`` token for an application that did not restrict the
  algorithms. This completes the fix for CVE-2026-114615.
  `GHSA-f7j6-p4qx-gq99 <https://github.com/authlib/authlib/security/advisories/GHSA-f7j6-p4qx-gq99>`_

.. _changelog-1.9.4:

Version 1.9.4 — 2026-11-04
--------------------------

Security
~~~~~~~~

- ``IDJAGGrant`` stores the verified claims of the ID-JAG in
  ``request.id_jag_claims``. ``authenticate_user`` can use them to resolve
  the user with the ``iss`` and ``sub`` claims, and ``tenant`` for a
  multi-tenant IdP. The documentation used to resolve the user with ``sub``
  alone. An IdP, or a tenant of an IdP, could then get access tokens for the
  users of another one. Update ``authenticate_user`` if your server trusts
  several IdPs or a multi-tenant IdP.
  `GHSA-9qr6-8289-9j56 <https://github.com/authlib/authlib/security/advisories/GHSA-9qr6-8289-9j56>`_

.. _changelog-1.9.3:

Version 1.9.3 — 2026-11-03
--------------------------

Security
~~~~~~~~

- The OpenID Connect implicit and hybrid grants refuse ``response_mode=form_post``
  when the redirect URI does not use the ``http`` or ``https`` scheme. They
  return an ``invalid_request`` error and do not redirect. A client with a
  ``javascript:`` redirect URI could run a script in the origin of the
  authorization server, even when the user denied the authorization.
  `GHSA-gp2m-377p-m4j3 <https://github.com/authlib/authlib/security/advisories/GHSA-gp2m-377p-m4j3>`_

.. _changelog-1.9.2:

Version 1.9.2 — 2026-11-01
--------------------------

Security
~~~~~~~~

- ``IDJAGGrant`` limits the access token to the scopes in the ``scope`` claim
  of the ID-JAG. A client used to get any scope allowed by its registration,
  even when the IdP granted fewer scopes. Without a ``scope`` request
  parameter, the access token now gets the scopes of the claim instead of no
  scope.
  `GHSA-f3fg-34g9-v7jx <https://github.com/authlib/authlib/security/advisories/GHSA-f3fg-34g9-v7jx>`_

.. _changelog-1.9.1:

Version 1.9.1 — 2026-10-14
--------------------------

Breaking changes
~~~~~~~~~~~~~~~~

- The RFC 7592 client configuration endpoint calls ``check_client()`` on the
  registration access token. Tokens must implement
  ``TokenMixin.check_client``.

Security
~~~~~~~~

- ``authlib.jose`` rejects empty HMAC keys with a ``ValueError``. An empty key
  used to let anyone forge HS256, HS384 and HS512 signatures. The minimum
  ``joserfc`` version is now 1.6.8, which has the same check.
  `GHSA-8m4g-j4wp-wgcg <https://github.com/authlib/authlib/security/advisories/GHSA-8m4g-j4wp-wgcg>`_
- The RFC 7592 client configuration endpoint rejects registration access
  tokens issued to another client, with an ``access_denied`` error. A client
  could read, update or delete the registration of any other client.
  `GHSA-c73q-w75p-j82v <https://github.com/authlib/authlib/security/advisories/GHSA-c73q-w75p-j82v>`_

Version 1.9.0
-------------

**Released on Oct 14, 2026**

- **Breaking change**: ID Tokens with ``nonce_supported=false`` no longer
  bypass validation of the nonce saved by the client. Missing or mismatched
  nonces are rejected in both synchronous and asynchronous integrations.
  Provider compatibility exceptions must be explicitly configured by the
  application, rather than enabled by an ID Token claim. :pr:`949`
- Enforce JAR ``require_signed_request_object`` independently of the signing
  algorithm configuration. An explicit algorithm list or a customized
  ``get_request_object_signing_algorithms()`` cannot allow ``alg=none`` when
  either the server or the client requires signed request objects. :pr:`949`
- **Breaking change**: JAR ``request_uri`` is validated before retrieval and
  rejected by default. Applications must implement ``validate_request_uri()``
  with an explicit secure retrieval policy. See :ref:`specs/rfc9101` for
  retrieval safeguards. :pr:`949`
- Add ``authlib.oidc.core.OpenIDJWTAuthenticationRequest`` to enforce OIDC
  ``require_request_uri_registration`` separately from the generic JAR
  retrieval policy. Registered URIs must also pass the application's
  validation policy. See :ref:`oidc_request_objects`. :pr:`949`
- Reject PEM and SSH key material used as symmetric JOSE keys, including
  PEM keys with leading whitespace, comments, or a byte-order mark and
  keys supplied through an oct JWK or an ``OctKey`` instance. :pr:`945`
- Use the client's allowed scope when validating and issuing OIDC implicit
  and hybrid responses. Clients without the ``openid`` scope can no longer
  obtain an ID Token by including it in the raw request, and custom token
  generators receive only the allowed scope. :pr:`945`
- **Breaking change**: ``JWTBearerGrant.get_audiences()`` must return a
  non-empty list of audience identifiers for the authorization server.
  Assertions are rejected with ``invalid_grant`` when audiences are not
  configured, instead of issuing a deprecation warning and skipping
  audience value validation. :pr:`945`
- Require client authentication for ID-JAG token requests and bind the
  assertion's ``client_id`` to the authenticated client. Missing or invalid
  credentials and client mismatches no longer allow token issuance. Rejected
  authentication and mismatches do not consume the assertion's replay identifier.
  :pr:`955`
- Add support for the Identity Assertion JWT Authorization Grant (ID-JAG),
  a draft extension to :rfc:`7523` for cross-application access using identity
  assertions issued by an external enterprise IdP.
  See :ref:`specs/rfc7523-id-jag` for details. :pr:`898`
- The async OpenID Connect client returns ``None`` from ``parse_id_token()``
  when the token has no ``id_token``, like the sync client. It used to raise
  a ``KeyError``. :pr:`924`
- OAuth 2 and assertion clients raise the HTTP error of the token endpoint
  response when its body is not a JSON object, such as a plain-text 429 page
  from a gateway. They used to raise a ``JSONDecodeError`` or a ``TypeError``.
  A success response with such a body raises a ``ValueError``.
  :issue:`928` :pr:`929`
- ``JsonWebSignature.deserialize_json()`` rejects a JWS JSON Serialization
  with an empty ``signatures`` list. It used to accept it as valid. :pr:`938`
- ``JWTClaims.validate()`` rejects boolean ``exp``, ``nbf`` and ``iat`` values
  with an ``InvalidClaimError``. :issue:`641` :pr:`942`
- OAuth 1.0 clients send each OAuth parameter once when the signature is
  placed in the query string or the form body. Duplicated parameters used to
  produce an invalid signature. :issue:`542` :pr:`943`

Version 1.8.0
-------------

**Released on Aug 30, 2026**

- **Breaking change**: ``authlib.integrations.httpx_client`` is now powered by
  ``httpx2`` instead of ``httpx``. Install ``httpx2`` to keep using this
  integration; the public import path and class names are unchanged. When
  ``httpx2`` is not installed, the integration falls back to ``httpx`` and emits
  an ``AuthlibDeprecationWarning``. This fallback will be removed in a future
  release. :issue:`904`
- **Breaking change**: the client metadata ``id_token_signed_response_alg``
  now takes precedence over ``get_jwt_config()["alg"]`` when signing OIDC
  ``id_token``, in line with `OpenID Connect Registration 1.0 Section 2
  <https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata>`_.
  ``get_jwt_config()["alg"]`` is now used as a server-wide default when the
  client did not configure an algorithm. Override
  ``get_client_algorithm(client)`` if you need the previous behaviour.
  :issue:`806`
- Fix ``is_secure_transport()`` accepting cleartext URIs whose ``userinfo``
  component looks like a loopback host, such as
  ``http://localhost:80@attacker.test/cb``. The loopback exemption is now
  matched on the parsed host, and no longer requires an explicit port.
- Reject URIs with a ``userinfo`` component during client and server metadata
  validation, as in ``https://client.test@attacker.test/cb``. URIs that
  ``urlparse`` refuses to parse, such as ``http://[not-an-ip]/``, are also
  rejected instead of raising an unhandled ``ValueError``.
- Cast the ``sub`` claim to a string in the RFC 9068 and RFC 7523
  ``JWTBearerTokenGenerator``, as required by RFC 7519 Section 4.1.2.
  ``joserfc`` 1.7.3 started validating this claim and rejected the previously
  emitted non-string values (e.g. an integer ``get_user_id()``).
  :issue:`910` :pr:`911`
- Require ``joserfc>=1.6.1`` and ``cryptography>=45.0.1``. The RFC 9068 ``amr``
  validation uses ``InvalidClaimError``'s ``description`` argument, added in
  ``joserfc`` 1.6.1.
- Declare lower bounds for the optional integration dependencies and test them
  in CI against their minimum versions with uv's ``lowest-direct`` resolution.
- The token endpoint answers malformed RFC 7523 assertions with an
  ``invalid_client`` or ``invalid_grant`` error instead of raising an unhandled
  exception. ``JWTBearerGrant.resolve_issuer_client()`` may return ``None`` for
  an unknown issuer.
- The RFC 9068 ``JWTBearerTokenValidator`` answers with an ``invalid_token``
  error for any ``JoseError`` raised while decoding an access token, instead of
  only ``DecodeError``. An unknown ``kid`` used to raise an unhandled
  ``InvalidKeyIdError``. :pr:`891`
- Add a ``leeway`` parameter to the RFC 7523 ``JWTBearerTokenValidator``, which
  used to be hardcoded to 60 seconds. :pr:`903`
- ``sign_jwt_bearer_assertion()`` generates a default ``jti`` claim when the
  caller did not provide one, as :rfc:`7523` §3 recommends against replay
  attacks. This matches what ``OAuth2Session`` already did for client
  assertions. :pr:`897`
- Add optional ``client_id`` parameter to ``AssertionClient`` (and its
  ``AssertionSession`` / httpx wrappers) so it can be sent in the token
  endpoint request body per :rfc:`7521` §4.1 and :rfc:`6749` §3.2.1. :pr:`476`
- The OpenID Connect client no longer rejects an ``id_token`` whose JWS header
  carries unregistered parameters. :issue:`902`
- Omit the ``nonce`` and ``auth_time`` claims from the ``id_token`` instead of
  emitting them with a ``null`` value. :issue:`921`
- ``DeviceAuthorizationEndpoint`` saves the device credential with the
  authenticated client id. It used to read ``request.payload.client_id``, which
  is ``None`` when the client authenticates with ``client_secret_basic``.
  :issue:`798` :pr:`908`
- Fix the OAuth 1.0a ``InsecureTransportError`` description telling users that
  OAuth 2 must use HTTPS. :pr:`919`

Version 1.7.2
-------------

**Released on May 6, 2026**

- Fix ``PrivateKeyJWT`` rejecting ``ECKey`` private keys (e.g. for ``ES256``).
  The client private key is no longer forcibly imported as an ``RSAKey``;
  ``joserfc``'s key auto-detection is used instead. :pr:`852`
- Allow ``ClientSecretJWT`` and ``PrivateKeyJWT`` to sign client assertions
  with non-recommended algorithms (e.g. ``RS384``) when explicitly set via the
  ``alg`` parameter. :issue:`883`
- Validate BCP 47 language tags in ``ui_locales_supported``, ``claims_locales_supported``
  and ``UserInfo.locale``. :pr:`873`

Version 1.7.1
-------------

**Released on May 4, 2026**

- Fix ``AuthlibDeprecationWarning`` being emitted on import when using integrations
  that do not use ``authlib.jose`` directly. :issue:`880`
- Fix redirecting to unvalidated ``redirect_uri`` on ``InvalidScopeError``
  in ``OpenIDImplicitGrant`` and ``OpenIDHybridGrant``.

Version 1.7.0
-------------

**Released on Apr 18, 2026**

- Add support for `OpenID Connect RP-Initiated Logout 1.0
  <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>`_.
  See :ref:`specs/rpinitiated` for details. :issue:`500`
- Per RFC 6749 Section 3.3, the ``scope`` parameter is now optional at both
  authorization and token endpoints. ``client.get_allowed_scope()`` is called
  to determine the default scope when omitted. :issue:`845`
- Stop support for Python 3.9, start support Python 3.14. :pr:`850`
- Allow ``AuthorizationServerMetadata.validate()`` to compose with RFC extension classes.
- Fix ``expires_at=0`` being incorrectly treated as ``None``. :issue:`530`
- Allow ``ResourceProtector`` decorator to be used without parentheses. :issue:`604`
- Implement RFC9700 PKCE downgrade countermeasure.
- Set ``User-Agent`` header when fetching server metadata and JWKs. :issue:`704`
- RFC7523 accepts the issuer URL as a valid audience. :issue:`730`
- Fix ``InvalidTokenError`` extra attributes being wrapped instead of passed as
  individual key=value pairs in the ``WWW-Authenticate`` header. :pr:`872`

Upgrade Guide: :ref:`joserfc_upgrade`.

Version 1.6.11
--------------

**Released on Apr 16, 2026**

- Fix CSRF vulnerability in the Starlette OAuth client when a ``cache`` is
  configured.

Version 1.6.10
--------------

**Released on Apr 13, 2026**

- Fix redirecting to unvalidated ``redirect_uri`` on ``UnsupportedResponseTypeError``.

Version 1.6.9
-------------

**Released on Mar 2, 2026**

- Not using header's ``jwk`` automatically.
- Add ``ES256K`` into default jwt algorithms.
- Remove deprecated algorithm from default registry.
- Generate random ``cek`` when ``cek`` length doesn't match.

Version 1.6.8
-------------

**Released on Feb 17, 2026**

- Add ``EdDSA`` to default ``jwt`` instance.

Version 1.6.7
-------------

**Released on Feb 6, 2026**

- Set supported algorithms for the default ``jwt`` instance.

Version 1.6.6
-------------

**Released on Jan 9, 2026**

- ``get_jwt_config`` takes a ``client`` parameter, :pr:`844`.
- Fix incorrect signature when ``Content-Type`` is x-www-form-urlencoded for OAuth 1.0 Client, :pr:`778`.
- Use ``expires_in`` in ``OAuth2Token`` when ``expires_at`` is unparsable, :pr:`842`.
- Always track ``state`` in session for OAuth client integrations.

Version 1.6.5
-------------

**Released on Oct 2, 2025**

- RFC7591 ``generate_client_info`` and ``generate_client_secret`` take a ``request`` parameter.
- Add size limitation when decode JWS/JWE to prevent DoS.
- Add size limitation for ``DEF`` JWE zip algorithm.

Version 1.6.4
-------------

**Released on Sep 17, 2025**

- Fix ``InsecureTransportError`` error raising. :issue:`795`
- Fix ``response_mode=form_post`` with Starlette client. :issue:`793`
- Validate ``crit`` header value, reject unprotected header in ``crit`` header.

Version 1.6.3
-------------

**Released on Aug 26, 2025**

- OIDC ``id_token`` are signed according to ``id_token_signed_response_alg``
  client metadata. :issue:`755`

Version 1.6.2
-------------

**Released on Aug 23, 2025**

- Temporarily restore ``OAuth2Request`` ``body`` parameter. :issue:`781` :pr:`791`
- Allow ``127.0.0.1`` in insecure transport mode. :pr:`788`
- Raise ``MissingCodeException`` when the ``code`` parameter is missing. :issue:`793` :pr:`794`
- Fix ``id_token`` generation with `EdDSA` algs. :issue:`799` :pr:`800`

Version 1.6.1
-------------

**Released on Jul 20, 2025**

- Filter key set with additional "alg" and "use" parameters.
- Restore and deprecate ``OAuth2Request`` ``body`` parameter. :issue:`781`

Version 1.6.0
-------------

**Released on May 22, 2025**

- Fix issue when :rfc:`RFC9207 <9207>` is enabled and the authorization endpoint response is not a redirection. :pr:`733`
- Fix missing ``state`` parameter in authorization error responses. :issue:`525`
- Support for the ``none`` JWS algorithm.
- Fix ``response_types`` strict order during dynamic client registration. :issue:`760`
- Implement :rfc:`RFC9101 The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR) <9101>`. :issue:`723`
- OIDC :class:`UserInfo endpoint <authlib.oidc.core.userinfo.UserInfoEndpoint>` support. :issue:`459`

**Breaking changes**:

- Support for ``acr`` and ``amr`` claims in ``id_token``. :issue:`734`
  The ``OAuth2AuthorizationCodeMixin`` must have a migration to support the new fields.

Version 1.5.2
-------------

**Released on Apr 1, 2025**

- Forbid fragments in ``redirect_uris``. :issue:`714`
- Fix invalid characters in ``error_description``. :issue:`720`
- Add ``claims_cls`` parameter for client's ``parse_id_token`` method. :issue:`725`

Version 1.5.1
-------------

**Released on Feb 28, 2025**

- Fix RFC9207 ``iss`` parameter. :pr:`715`

Version 1.5.0
-------------

**Released on Feb 25, 2025**

- Fix token introspection auth method for clients. :pr:`662`
- Optional ``typ`` claim in JWT tokens. :pr:`696`
- JWT validation leeway. :pr:`689`
- Implement server-side :rfc:`RFC9207 <9207>`. :issue:`700` :pr:`701`
- ``generate_id_token`` can take a ``kid`` parameter. :pr:`702`
- More detailed ``InvalidClientError``. :pr:`706`
- OpenID Connect Dynamic Client Registration implementation. :pr:`707`

Version 1.4.1
-------------

**Released on Jan 28, 2025**

- Improve garbage collection on OAuth clients. :issue:`698`
- Fix client parameters for httpx. :issue:`694`

Version 1.4.0
-------------

**Released on Dec 20, 2024**

- Fix ``id_token`` decoding when kid is null. :pr:`659`
- Support for Python 3.13. :pr:`682`
- Force login if the ``prompt`` parameter value is ``login``. :pr:`637`
- Support for httpx 0.28, :pr:`695`

**Breaking changes**:

- Stop support for Python 3.8. :pr:`682`

Version 1.3.2
-------------

**Released on Aug 30 2024**

- Prevent ever-growing session size for OAuth clients.
- Revert ``quote`` client id and secret.
- ``unquote`` basic auth header for authorization server.

Version 1.3.1
-------------

**Released on June 4, 2024**

- Prevent ``OctKey`` to import ssh and PEM strings.


Version 1.3.0
-------------

**Released on Dec 17, 2023**

- Restore ``AuthorizationServer.create_authorization_response`` behavior, via :PR:`558`
- Include ``leeway`` in ``validate_iat()`` for JWT, via :PR:`565`
- Fix ``encode_client_secret_basic``, via :PR:`594`
- Use single key in JWK if JWS does not specify ``kid``, via :PR:`596`
- Fix error when RFC9068 JWS has no scope field, via :PR:`598`
- Get werkzeug version using importlib, via :PR:`591`

**New features**:

- RFC9068 implementation, via :PR:`586`, by @azmeuk.

**Breaking changes**:

- End support for python 3.7

Version 1.2.1
-------------

**Released on Jun 25, 2023**

- Apply headers in ``ClientSecretJWT.sign`` method, via :PR:`552`
- Allow falsy but non-None grant uri params, via :PR:`544`
- Fixed ``authorize_redirect`` for Starlette v0.26.0, via :PR:`533`
- Removed ``has_client_secret`` method and documentation, via :PR:`513`
- Removed ``request_invalid`` and ``token_revoked`` remaining occurrences
  and documentation. :PR:`514`
- Fixed RFC7591 ``grant_types`` and ``response_types`` default values, via :PR:`509`.
- Add support for python 3.12, via :PR:`590`.

Version 1.2.0
-------------

**Released on Dec 6, 2022**

- Not passing ``request.body`` to ``ResourceProtector``, via :issue:`485`.
- Use ``flask.g`` instead of ``_app_ctx_stack``, via :issue:`482`.
- Add ``headers`` parameter back to ``ClientSecretJWT``, via :issue:`457`.
- Always passing ``realm`` parameter in OAuth 1 clients, via :issue:`339`.
- Implemented RFC7592 Dynamic Client Registration Management Protocol, via :PR:`505`.
- Add ``default_timeout`` for requests ``OAuth2Session`` and ``AssertionSession``.
- Deprecate ``jwk.loads`` and ``jwk.dumps``

Version 1.1.0
-------------

**Released on Sep 13, 2022**

This release contains breaking changes and security fixes.

- Allow to pass ``claims_options`` to Framework OpenID Connect clients, via :PR:`446`.
- Fix ``.stream`` with context for HTTPX OAuth clients, via :PR:`465`.
- Fix Starlette OAuth client for cache store, via :PR:`478`.

**Breaking changes**:

- Raise ``InvalidGrantError`` for invalid code, redirect_uri and no user errors in OAuth
  2.0 server.
- The default ``authlib.jose.jwt`` would only work with JSON Web Signature algorithms, if
  you would like to use JWT with JWE algorithms, please pass the algorithms parameter:

  .. code-block:: python

      jwt = JsonWebToken(['A128KW', 'A128GCM', 'DEF'])

**Security fixes**: CVE-2022-39175 and CVE-2022-39174, both related to JOSE.

Version 1.0.1
-------------

**Released on Apr 6, 2022**

- Fix authenticate_none method, via :issue:`438`.
- Allow to pass in alternative signing algorithm to RFC7523 authentication methods via :PR:`447`.
- Fix ``missing_token`` for Flask OAuth client, via :issue:`448`.
- Allow ``openid`` in any place of the scope, via :issue:`449`.
- Security fix for validating essential value on blank value in JWT, via :issue:`445`.


Version 1.0.0
-------------

**Released on Mar 15, 2022.**

We have dropped support for Python 2 in this release. We have removed
built-in SQLAlchemy integration.

**OAuth Client Changes:**

The whole framework client integrations have been restructured, if you are
using the client properly, e.g. ``oauth.register(...)``, it would work as
before.

**OAuth Provider Changes:**

In Flask OAuth 2.0 provider, we have removed the deprecated
``OAUTH2_JWT_XXX`` configuration, instead, developers should define
`.get_jwt_config` on OpenID extensions and grant types.

**SQLAlchemy** integrations has been removed from Authlib. Developers
should define the database by themselves.

**JOSE Changes**

- ``JWS`` has been renamed to ``JsonWebSignature``
- ``JWE`` has been renamed to ``JsonWebEncryption``
- ``JWK`` has been renamed to ``JsonWebKey``
- ``JWT`` has been renamed to ``JsonWebToken``

The "Key" model has been re-designed, checkout the :ref:`jwk_guide` for updates.

Added ``ES256K`` algorithm for JWS and JWT.

**Breaking Changes**: find how to solve the deprecate issues via https://git.io/JkY4f


.. scriv-end-here

Old Versions
------------

Find old changelog at https://github.com/authlib/authlib/releases

- Version 0.15.5: Released on Oct 18, 2021
- Version 0.15.4: Released on Jul 17, 2021
- Version 0.15.3: Released on Jan 15, 2021
- Version 0.15.2: Released on Oct 18, 2020
- Version 0.15.1: Released on Oct 14, 2020
- Version 0.15.0: Released on Oct 10, 2020
- Version 0.14.3: Released on May 18, 2020
- Version 0.14.2: Released on May 6, 2020
- Version 0.14.1: Released on Feb 12, 2020
- Version 0.14.0: Released on Feb 11, 2020
- Version 0.13.0: Released on Nov 11, 2019
- Version 0.12.0: Released on Sep 3, 2019
- Version 0.11.0: Released on Apr 6, 2019
- Version 0.10.0: Released on Oct 12, 2018
- Version 0.9.0: Released on Aug 12, 2018
- Version 0.8.0: Released on Jun 17, 2018
- Version 0.7.0: Released on Apr 28, 2018
- Version 0.6.0: Released on Mar 20, 2018
- Version 0.5.1: Released on Feb 11, 2018
- Version 0.5.0: Released on Feb 11, 2018
- Version 0.4.1: Released on Feb 2, 2018
- Version 0.4.0: Released on Jan 31, 2018
- Version 0.3.0: Released on Dec 24, 2017
- Version 0.2.1: Released on Dec 6, 2017
- Version 0.2.0: Released on Nov 25, 2017
- Version 0.1.0: Released on Nov 18, 2017
