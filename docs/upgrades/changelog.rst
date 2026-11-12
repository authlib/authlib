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

- The RFC 7591 registration endpoint and the RFC 7592 configuration endpoint
  respond with HTTP 401 to token errors, per :rfc:`7591#section-3.2.2`,
  :rfc:`7592#section-2.1` and :rfc:`6750#section-3`. A request without
  ``Authorization`` header gets no error code. The other token errors get
  ``invalid_token``, such as a token of another client. Both endpoints used to
  respond with HTTP 400 ``access_denied``. :pr:`979`
- The RFC 7592 configuration endpoint passes ``token`` and ``request`` to
  ``revoke_access_token`` by name. It used to pass them in the reverse order
  of the documentation. Overrides must name their parameters ``token`` and
  ``request``. :pr:`979`
- ``ResourceProtector`` responds with HTTP 401, a ``WWW-Authenticate: Bearer``
  header and no error code to a request without ``Authorization`` header or
  with an unsupported scheme, per :rfc:`6750#section-3.1`. It used to send a
  ``missing_authorization`` or ``unsupported_token_type`` error. Both cases
  raise ``MissingAuthorizationError``, so with ``optional=True``, an
  unsupported scheme counts as a missing token.
  :pr:`956`
- Revocation and introspection endpoints ignore an unknown
  ``token_type_hint``, per :rfc:`7009#section-2.2` and
  :rfc:`7662#section-2.1`. They used to respond with
  ``unsupported_token_type``. :pr:`1006`
- Revocation and introspection endpoints search the other token types when
  the token is not found with the ``token_type_hint``, per
  :rfc:`7009#section-2.1` and :rfc:`7662#section-2.1`. A refresh token sent
  with an ``access_token`` hint used to stay active. Custom ``revoke_token``
  methods must not trust the hint. :pr:`1006`
- ``UnsupportedTokenTypeError`` responds with HTTP 400 instead of 401, per
  :rfc:`7009#section-2.2.1`. It inherits from ``OAuth2Error`` instead of
  ``ForbiddenError``, and no longer takes ``auth_type`` and ``realm``.
  :pr:`1006`
- The :rfc:`9068` revocation and introspection endpoints only handle JWTs with
  the ``at+jwt`` ``typ``, whatever the hint. Other JWTs, such as JWT refresh
  tokens, go to the next endpoint. :pr:`1006`
- The SQLAlchemy revocation endpoint ignores the hint. Revoking an access
  token keeps the refresh token active. Revoking a refresh token also revokes
  the access token, per :rfc:`7009#section-2.1`. :pr:`1006`
- The ``get_audiences`` method of ``JWTBearerClientAssertion`` and of
  ``IDJAGGrant`` must return a non-empty list. An empty list used to skip the
  ``aud`` check. The assertions are now rejected.
- Hooks run around the most derived override of a method, even when it does
  not call ``super()``. An ``after`` hook gets the result of the override. For
  instance, ``OpenIDCode`` now adds the ``id_token`` when
  ``create_token_response`` is overridden. :pr:`978`
- Only ``Hookable`` classes run hooks. A method of a mixin that is not
  ``Hookable`` no longer runs hooks, even with ``hooked``, and registering a
  hook on it raises a ``TypeError``. Make the mixin inherit from ``Hookable``.
  A mixin method that overrides a method of a ``Hookable`` class still runs
  hooks. :pr:`978`
- ``register_hook`` raises a ``TypeError`` for a static method, a class method
  or a property, and when ``hook_type`` and ``hook`` are passed by name.
  ``hooked`` raises a ``TypeError`` with custom hook names. :pr:`978`
- The OpenID Connect implicit and hybrid flows only accept the ``fragment``
  and ``form_post`` response modes, per OAuth 2.0 Multiple Response Type
  Encoding Practices §5. Other values, ``query`` included, get an
  ``invalid_request`` error in the fragment, before the user consent. An
  unknown value used to raise a ``ValueError``. :pr:`980`
- Without the ``MultipleResponseTypes`` extension, the OpenID Connect implicit
  and hybrid flows send ``access_denied`` in the fragment, like the other
  errors, even with ``response_mode=form_post``. :pr:`1000`
- ``IssuerParameter.add_issuer_parameter`` receives an
  ``AuthorizationResponse`` and adds ``iss`` to its ``params``. It used to
  change the ``Location`` header of the framework response. Custom grants must
  return an ``AuthorizationResponse`` to get ``iss``. :pr:`987`
- ``OAuth2AuthorizationCodeMixin`` has an ``issued_at`` column, used by
  ``is_expired``. ``auth_time`` is now the time of the user authentication,
  and it is nullable. In your migration, add ``issued_at``, copy the
  ``auth_time`` values into it, and make ``auth_time`` nullable. :issue:`741`
- Stop supporting Python 3.10. Authlib supports Python 3.11 to 3.15.
  :pr:`991`
- ``get_consent_grant`` calls the new ``validate_interactions`` method of the
  grant. Overrides of ``get_consent_grant`` must call it too. :issue:`740`
- When the request asks for several interactions, ``grant.prompt`` follows the
  order of ``grant.interactions``. For instance, with
  ``prompt=consent select_account``, it is ``"select_account"`` instead of
  ``"consent"``. :issue:`740`
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
- An anonymous user is not redirected to the client with an error, per
  :rfc:`9700#section-4.11.2`. ``get_consent_grant`` returns the grant with the
  ``"login"`` interaction, and raises the error after the login.
  ``create_authorization_response`` returns the error of such a grant without
  redirection, and never issues a code. An anonymous user gets
  ``unsupported_response_type`` without redirection. With the
  OpenID Connect ``prompt=none``, errors are still redirected at once. If you
  do not pass the user to ``get_consent_grant``, all the users are anonymous.
  Set ``server.defer_anonymous_errors = False`` to keep the previous behavior.
  :pr:`1000`
- The implicit grant looks the client up with the new
  ``query_authorization_client`` method, like the authorization code grant. It
  no longer authenticates the client, so overrides of
  ``authenticate_token_endpoint_client`` and ``TOKEN_ENDPOINT_AUTH_METHODS``
  do not apply to it, and the ``client_authenticated`` signal is not sent. To
  restrict the clients, override ``query_authorization_client`` or
  ``check_response_type``. :issue:`759`
- The OpenID Connect UserInfo endpoint reads the token scope with
  ``get_scope()``. Custom token classes must implement it. :issue:`831`
- When the provider metadata has no ``id_token_signing_alg_values_supported``,
  the synchronous OpenID Connect client accepts only ``RS256`` ID tokens, like
  the asynchronous client. For another algorithm, set this metadata in
  ``register``. Both clients refuse unsigned ID tokens, even when the provider
  lists ``none``.
- OpenID Connect ID tokens are refused when ``aud`` does not contain the
  client ID, even with a matching ``azp`` claim, per OpenID Connect Core
  §3.1.3.7.
- The :rfc:`9068` ``JWTBearerTokenValidator`` refuses a JWT access token
  without a ``typ`` header, per :rfc:`9068#section-4`. Another JWT without
  ``typ`` from the same issuer, such as an ID token, used to be accepted as an
  access token.
- The OAuth 2 clients raise a ``ValueError`` when ``code_challenge_method`` is
  not ``S256`` or ``plain``. They used to skip PKCE. :issue:`709`
- The OAuth 2 and OpenID Connect authorization server redirects with a 303
  status code instead of 302, per :rfc:`9700#section-4.12`. This covers the
  authorization responses, the errors sent to the redirect URI, and the
  RP-Initiated Logout redirection. :pr:`1016`
- ``authlib.jose`` rejects JWS and JWE segments that are not canonical
  base64url, such as a signature with padding or a trailing newline. Strip a
  token read from a file before decoding it.
- Client registration and :rfc:`7592` updates reject a ``jwks`` that contains
  a symmetric or private key, per :rfc:`7591#section-2`. Registered clients
  with such keys must replace them before they can update their metadata.
- ``JsonWebEncryption`` rejects a JWE whose ``crit`` header lists an unknown
  header parameter, or is not in the protected header, like
  ``JsonWebSignature``. Add the private header parameters listed in ``crit``
  to ``private_headers``.
- The RFC 7523 ``JWTBearerTokenValidator`` rejects tokens with an ``aud``
  claim, unless its new ``audience`` parameter is set and ``aud`` contains it,
  per RFC 7519 §4.1.3. The tokens of ``JWTBearerTokenGenerator`` have no
  ``aud``. If your tokens have one, pass the identifier of your resource
  server as ``audience``. :pr:`1038`
- JAR request objects and software statements with an ``aud`` claim are
  rejected when ``aud`` contains no value of the new ``get_audiences`` method
  of ``JWTAuthenticationRequest`` and ``ClientRegistrationEndpoint``. By
  default, it returns the ``issuer`` of the server metadata. Objects without
  ``aud`` are still accepted. If your clients send ``aud``, add ``issuer`` to
  ``get_server_metadata``, or override ``get_audiences``. :pr:`1038`
- The client checks the ``issuer`` of the discovery document, per RFC 8414
  §3.3 and OpenID Connect Discovery §4.3. It must be the issuer that
  ``server_metadata_url`` is built from, or the ``issuer`` given to
  ``register``. Otherwise, the client raises ``MismatchingIssuerError``.
  Providers that serve another issuer, such as the Microsoft multi-tenant
  endpoints, need the ``issuer`` parameter, also set with ``{name}_ISSUER`` in
  the Flask and Starlette configuration. The document no longer replaces an
  ``issuer`` given to ``register``. :pr:`1046`

Added
~~~~~

- The Requests and HTTPX OAuth 2 clients fetch the first ``client_credentials``
  token by themselves when a token endpoint is configured. :pr:`946`
- ``OAuth2Session``, the HTTPX OAuth 2 clients and the assertion clients accept
  ``access_token_params``, extra parameters for the token request such as
  ``audience`` or ``resource``. They are also sent when a new token is fetched
  automatically. :issue:`783`
- Support Python 3.15. :pr:`958`
- ``ClientSecretJWT`` and ``PrivateKeyJWT`` accept an ``expires_in`` parameter
  for the lifetime of the client assertion. It used to be 3600 seconds.
  :issue:`857`
- The OpenID Connect client verifies signed UserInfo responses, per OpenID
  Connect Core §5.3.2. A ``userinfo_signed_response_alg`` given to
  ``register`` restricts the algorithm and refuses unsigned responses.
  :issue:`941`
- The documentation covers the ``OAuth2Session`` options of ``client_kwargs``
  such as ``leeway`` (:issue:`687`), the custom claims of the OpenID Connect
  client (:issue:`621`), and JWT access tokens from several issuers in the
  Flask resource server (:issue:`671`).
- Support `OpenID Connect Back-Channel Logout 1.0
  <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_. See
  :ref:`specs/backchannel`. :issue:`560`
- Support :rfc:`9728` OAuth 2.0 Protected Resource Metadata, for resource
  servers and authorization servers. :issue:`752`
- The ``FormEncodedBodyToken`` resource protector extension accepts the access
  token in a form-encoded request body, per :rfc:`6750#section-2.2`.
  :issue:`756`
- Hooks can run before, after or instead of any method of a ``Hookable``
  class, such as a grant, an authorization server or a resource protector.
  Register them with a reference to the method, such as
  ``after=AuthorizationCodeGrant.validate_token_request``. Hook names such as
  ``"after_validate_token_request"`` still work. :pr:`978`
- The ``PromptValues`` extension supports ``prompt=create`` from Initiating
  User Registration via OpenID Connect 1.0, and the ``prompt_values_supported``
  metadata. Unsupported values get ``invalid_request``. See
  :ref:`specs/prompt_create`. :issue:`735`
- The ``MultipleResponseTypes`` extension implements OAuth 2.0 Multiple
  Response Type Encoding Practices. Clients choose the response mode of any
  authorization grant with ``response_mode``, errors included. The server
  accepts the modes of ``response_modes_supported``, and never sends tokens in
  the query. See :doc:`/oauth2/specs/multiple-response-types`. :pr:`985`
- The ``FormPost`` extension implements OAuth 2.0 Form Post Response Mode for
  any authorization grant. A grant can use it by default with
  ``RESPONSE_MODE = "form_post"``. See :ref:`specs/form_post`. :pr:`986`
- ``NoneResponseTypeGrant`` supports ``response_type=none``. The client
  receives ``state``, and no code or token. :pr:`988`
- Grants and endpoints return an ``OAuth2Response``, such as a
  ``JsonResponse``, a ``RedirectResponse`` or an ``AuthorizationResponse``.
  :pr:`983` :pr:`984`
- The OpenID Connect grants enforce ``max_age`` and the ``default_max_age``
  client metadata, with the login time of the authorization session. The
  ``StepUpAuthentication`` extension of :rfc:`9470` also enforces ``max_age``
  without the ``openid`` scope. When the last login is too old, the user must
  log in again, and ``prompt=none`` gets ``login_required``. ``max_age=0``
  works like ``prompt=login``, and an invalid ``max_age`` gets
  ``invalid_request``. ``OAuth2ClientMixin`` has a ``default_max_age``
  property. See :ref:`authorization_session`. :issue:`741`
- The Flask and Django OAuth 2.0 requests give the request of the framework
  with ``framework_request``. :issue:`741`
- Grants and extensions declare the authorization request parameters they add
  with ``register_authorization_parameters``.
  ``AuthorizationServer.authorization_parameters`` lists them with their JSON
  types. :pr:`992` :pr:`994`
- ``grant.interactions`` lists the interactions the user must go through
  before the authorization response: ``"create"``, ``"login"``,
  ``"select_account"`` and ``"consent"``, in this order. ``grant.prompt`` is
  the first of them. :issue:`740`
- ``AuthorizationSessionMixin`` tells Authlib when the user last logged in,
  gave consent and selected an account. Pass it to
  ``get_consent_grant(session=...)``. An interaction that the client asks for,
  such as ``prompt=login``, is not asked again once done.
  ``authlib.oauth2.AuthorizationSession`` keeps the start time of the requests
  in the session of the web framework. See :ref:`authorization_session`.
  :issue:`740`
- With ``prompt=none``, the OpenID Connect grants return
  ``consent_required`` or ``account_selection_required`` when the user must
  give consent or select an account. :issue:`740`
- ``request.authorization_key`` identifies an authorization request across its
  HTTP requests, for instance before and after a login. :issue:`740`
- ``IDJAGGrant.resolve_user`` and ``IDJAGGrant.check_id_jag_permission``
  receive the verified claims of the ID-JAG.
- ``AuthorizationSessionMixin.can_redirect_error`` tells if an error can be
  sent to the redirect URI of the client. Return false for the redirect URIs
  you do not trust, per :rfc:`9700#section-4.11.2`. The error, even
  ``access_denied``, is then returned without redirection. :pr:`1000`
- ``grant.silent`` is true when the request must be done without any user
  interaction, such as with the OpenID Connect ``prompt=none``. :pr:`1000`
- ``grant.interactions`` contains ``"login"`` when the user is not logged in,
  also without OpenID Connect. :pr:`1000`
- ``CodeChallenge.is_code_challenge_required`` tells whether a client must use
  PKCE. Override it to require PKCE for all clients, as recommended by
  :rfc:`RFC 9700 §2.1.1 <9700#section-2.1.1>`. :issue:`1012`
- ``OAuth.remove_client(name)`` removes a registered remote application.
  :issue:`583`
- The Requests and HTTPX OAuth 1 and OAuth 2 clients accept URL objects, such
  as ``httpx.URL``, for the endpoints, the redirect URI and the authorization
  response. :issue:`931`
- The Requests clients accept ``headers``, sent with every request of the
  session, like the HTTPX clients. With the web clients,
  ``client_kwargs={"headers": ...}`` also applies to the
  ``server_metadata_url`` and ``jwks_uri`` requests. :issue:`633`
- The authorization session gives the ``acr`` and ``amr`` of the
  authentication with ``get_acr(request)`` and ``get_amr()``. The OpenID
  Connect grants put them in the ID token, in all flows. In the code flow,
  store ``request.acr`` and ``request.amr`` in ``save_authorization_code``.
  The documentation explains how to answer the ``acr_values`` parameter.
  :issue:`744`
- ``UnmetAuthenticationRequirementsError`` refuses a request whose
  authentication requirements cannot be met, per the OpenID Connect Core
  Error Code unmet_authentication_requirements specification. :issue:`744`
- ``AuthorizationCodeGrant.revoke_authorization_code_tokens(code, client)`` is
  called when a code is not found, for instance when it is reused. Implement
  it to revoke the tokens issued with this code, per RFC 6749 §4.1.2.
  :issue:`757`
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

Changed
~~~~~~~

- With Flask, the client registration and configuration endpoints read the
  body as JSON whatever the ``Content-Type``, as with Django. Another
  ``Content-Type`` used to get an HTTP 415 error page.

Deprecated
~~~~~~~~~~

- ``authlib.oauth2.rfc6749.hooks.hooked`` is deprecated and does nothing. It
  will be removed in 1.11. :pr:`978`
- Using ``response_mode`` with the OpenID Connect implicit and hybrid grants
  without the ``MultipleResponseTypes`` extension is deprecated. Register it
  with ``server.register_extension(MultipleResponseTypes())``. It will stop
  working in 1.11. :pr:`985`
- ``DEFAULT_RESPONSE_MODE`` of the OpenID Connect implicit and hybrid grants
  is deprecated. Use ``RESPONSE_MODE``. ``create_response_mode_response`` of
  ``authlib.oidc.core.grants.util`` is deprecated too. Return an
  ``AuthorizationResponse``. Both will be removed in 1.11. :pr:`986`
- Returning a ``(status_code, body, headers)`` tuple from a grant or an
  endpoint is deprecated. Return an ``OAuth2Response``. Unpacking an
  ``OAuth2Response`` as such a tuple is deprecated too, and will stop working
  in 1.11. Use its ``status_code``, ``body`` and ``headers`` attributes.
  :pr:`983`
- Using the OpenID Connect grants without an authorization session is
  deprecated. It will be required in 1.11. Until then, ``max_age`` is only
  enforced when it is ``0``, and ``auth_time`` is the current time.
  :issue:`741`
- Setting ``grant.prompt`` is deprecated. Read ``grant.interactions``
  instead. :issue:`740`
- ``IDJAGGrant.authenticate_user``, ``check_id_jag_permission`` without a
  ``claims`` argument, and ``request.id_jag_claims`` are deprecated. Implement
  ``resolve_user`` and use the ``claims`` argument instead.
- The default ``JWTBearerTokenGenerator.get_audiences`` puts the client ID in
  the ``aud`` claim. Per :rfc:`9068#section-3`, ``aud`` is the resource that
  receives the token. Override ``get_audiences`` to return it. In 1.11, the
  default will raise ``NotImplementedError``. :issue:`1004`
- The ``required`` parameter of ``CodeChallenge`` is deprecated. Override
  ``is_code_challenge_required`` instead. It will stop working in 1.11.
  :issue:`1012`
- Access token generators without an ``expires_in`` parameter are deprecated.
  In 1.11, they will always receive it. Add it to the function of
  ``OAUTH2_ACCESS_TOKEN_GENERATOR`` (Flask) or ``access_token_generator``
  (Django), and to the ``access_token_generator`` overrides of
  ``JWTBearerTokenGenerator``.
- ``authlib.oauth2.rfc7523.JWTBearerTokenGenerator`` and
  ``JWTBearerTokenValidator`` are deprecated. Use the classes of the same name
  in ``authlib.oauth2.rfc9068``. The generator will be removed in 1.11, and
  the validator in 2.0. :issue:`846`
- ``generate_user_info`` methods without a ``claims`` argument are deprecated.
  In 1.11, they will always receive it. :issue:`758`

Fixed
~~~~~

- ``fetch_token(grant_type="client_credentials")`` remembers the grant, so an
  expired token is fetched again. It used to raise ``InvalidTokenError``.
  :issue:`660`
- The OAuth 2 web clients send ``access_token_params`` when they fetch a new
  ``client_credentials`` token on expiry. They used to drop them. :issue:`783`
- ``AsyncOAuth2Client`` no longer refreshes with an outdated refresh token when
  concurrent requests find an expired token. :pr:`963`
- A JAR request object with a parameter of the wrong JSON type, such as a
  ``response_type`` list, gets ``invalid_request_object``. It used to raise a
  ``TypeError``. :pr:`970`
- An ID-JAG assertion whose payload is not a JSON object, or whose ``iss`` is
  not a string, gets ``invalid_grant`` instead of an HTTP 500 error.
- A client assertion, a JWT bearer assertion or an ID-JAG assertion with
  deeply nested JSON gets ``invalid_client`` or ``invalid_grant`` instead of
  an HTTP 500 error.
- ``Authorization: Basic`` credentials that are not valid UTF-8 get
  ``invalid_client``. They used to raise a ``UnicodeDecodeError``. :pr:`999`
- A non-ASCII ``client_secret`` gets ``invalid_client`` with the SQLAlchemy
  client mixin. It used to raise a ``TypeError``.
- The client registration and configuration endpoints return
  ``invalid_request`` for a body that is not a JSON object, instead of an HTTP
  500 error.
- ``AssertionSession``, ``ClientSecretJWT`` and ``PrivateKeyJWT`` send a new
  ``jti`` with each assertion when they are given ``claims``. They used to
  send the first ``jti`` again, and providers that check it rejected the next
  token requests as replays. :pr:`965`
- ``create_authorization_response``, ``create_token_response`` and
  ``create_endpoint_response`` return an ``insecure_transport`` error response
  for a plain HTTP request. They used to raise ``InsecureTransportError``.
  :issue:`973`
- Hooks run in the order they are registered. The order used to be random.
  :pr:`978`
- The HTTPX clients no longer raise a ``TypeError`` when an instrumentation
  library, such as ``opentelemetry-instrumentation-httpx`` or
  ``aws-xray-sdk``, has patched the httpx client classes. :issue:`557`
- The ``form_post`` response sends the parameters unchanged, and forbids
  caching with ``Cache-Control: no-store``. The parameters used to be
  percent-encoded, so the client could receive a modified ``state`` or
  ``error_description``. :pr:`980`
- The OpenID Connect implicit and hybrid flows return ``state`` when the user
  denies the request. :pr:`980`
- ``IssuerParameter`` adds ``iss`` to the fragment of fragment responses, and
  to the form of ``form_post`` responses. It used to put it in the query of
  fragment responses, and to omit it in ``form_post`` responses and in the
  errors of the consent page. :pr:`987`
- The hybrid flow sends its errors in the fragment instead of the query, for a
  missing ``nonce``, an unsupported scope and an unauthorized
  ``response_type``.
- Dynamic client registration refuses metadata of an unexpected type, such as
  a ``scope`` that is not a string, with ``invalid_client_metadata``. It used
  to cause a server error, or to register the value. A ``null`` value is
  ignored. An ``http`` post logout redirect URI of a public client also gets
  ``invalid_client_metadata`` instead of a ``ValueError``.
- Dynamic client registration refuses the ``none``
  ``id_token_signed_response_alg`` when the ``response_types`` return an ID
  token from the authorization endpoint, per OpenID Connect Dynamic Client
  Registration §2. This check never applied. :pr:`981`
- OpenID Connect client registration requires https ``request_uris`` for
  unsigned request objects. ``AUTHLIB_INSECURE_TRANSPORT`` allows http for
  development.
- Dynamic client registration refuses an expired software statement, or one
  whose ``nbf`` or ``iat`` is in the future, with
  ``invalid_software_statement``. ``software_statement_leeway`` allows 60
  seconds of clock skew by default.
- The order of the values of a ``response_type`` does not matter anymore, per
  RFC 6749 §3.1.1. This applies to the ``RESPONSE_TYPES`` of the grants, to
  the ``response_types`` of the SQLAlchemy client mixin, and to
  ``get_claim_cls_by_response_type``. :pr:`982`
- The ``auth_time`` claim of the ID token is the login time of the user. It
  used to be the time the ID token or the code was created. In the code and
  hybrid flows, store ``request.auth_time`` in ``save_authorization_code``.
  When the time is unknown, the ID token has no ``auth_time``. :issue:`741`
- An authorization request that repeats a parameter gets an
  ``invalid_request`` error, per RFC 6749 §3.1. Only the RFC 6749 parameters
  used to be checked. This now covers the parameters of the extensions, such
  as ``nonce``, ``code_challenge`` or ``request_uri``. With JAR, the request
  object is then not fetched. :pr:`992` :pr:`994`
- With a ``cache``, the Flask, Django and Starlette clients refuse an unknown
  ``state`` with ``MismatchingStateError``. They no longer pass it to the
  cache, whose backend could reject it with an unhandled error.
- ``IDJAGGrant`` rejects a ``tenant`` claim that is not a string with
  ``invalid_grant``.
- With a request object (:rfc:`9101`), the errors of
  ``create_authorization_response``, such as ``access_denied``, contain the
  ``state`` of the request object. :pr:`1000`
- A client registered with a ``token_endpoint_auth_method`` other than
  ``none`` can use the implicit grant. :issue:`759`
- The OpenID Connect UserInfo endpoint accepts :rfc:`9068` JWT access tokens.
  Override its new ``get_token_client`` and ``get_token_user`` methods to load
  the client and the user from the token claims. :issue:`831`
- ``parse_id_token`` keeps the issuer check when ``claims_options`` does not
  check ``iss`` itself. It no longer modifies ``claims_options``.
- The RP-Initiated Logout endpoint refuses an unsigned ``id_token_hint``, even
  when the server JWKS has an ``oct`` key or ``get_algorithms`` returns
  ``none``. It also refuses a logout token, and a JWT that declares another
  ``typ`` than ``JWT``, like an access token.
- The client authentication debug logs quote the ``client_id``, so a
  ``client_id`` with a line feed can no longer add fake lines to the logs.
- The size limits of ``authlib.jose`` raise ``ExceededSizeError``, a
  ``JoseError``, so an application that catches ``JoseError`` refuses a too
  long token instead of failing. It is also a ``ValueError``, as before.
- An ID token with an unknown ``kid`` fetches the JWK set of the provider at
  most once per ``jwks_refresh_interval``, 60 seconds by default. It used to
  fetch it for every such ID token.
- The Requests and HTTPX OAuth 2 clients send all the values of the
  ``resource`` (:rfc:`8707`) and ``audience`` (:rfc:`8693`) parameters. They
  used to send only the last one. ``fetch_token`` and ``refresh_token`` also
  accept a list for these parameters. :pr:`1010`
- When PKCE is required, the authorization endpoint rejects a public client
  without ``code_challenge``, per :rfc:`7636#section-4.4.1`. The error used to
  come at the token endpoint, after the login and the consent. :pr:`1013`
- The authorization endpoint rejects a request without
  ``code_challenge_method`` when ``plain`` is not supported. Per
  :rfc:`7636#section-4.3`, a missing method means ``plain``. Such requests
  used to be accepted. :pr:`1013`
- The OAuth 2 clients support the ``plain`` PKCE method, and add the PKCE
  challenge for a ``response_type`` that contains ``code``, such as
  ``code id_token``. They used to send a ``code_verifier`` without
  ``code_challenge``, and the server rejected the request. :issue:`709`
- Registering a remote application with a name that is already registered
  replaces it. It used to return the first client. :issue:`583`
- Registering a remote application no longer changes
  ``client_cls.OAUTH_APP_CONFIG`` or the dicts given to ``register``, such as
  ``client_kwargs``. :issue:`583`
- ``PrivateKeyJWT`` accepts an EC or OKP private key as a PEM string or a JWK
  dict. It used to import every key as an RSA key. :pr:`1018`
- The JWT assertions signed by Authlib carry the ``kid`` of the key, unless the
  header sets one, per OpenID Connect Core §10.1. This covers
  ``PrivateKeyJWT``, ``ClientSecretJWT``, the JWT bearer grants and ID-JAG.
  :pr:`1018`
- Signing a JWT assertion no longer adds ``alg`` to the ``headers`` dict of
  the caller. :pr:`1018`
- The Flask, Django and Starlette clients raise an ``OAuthError`` for an error
  response sent with ``response_mode=form_post``. They used to ignore it and
  fetch a token without a code. The ``OAuthError`` of an authorization error
  response carries its ``error_uri`` as ``uri``. :pr:`1020`
- The documentation of the RFC 7591 and RFC 7592 endpoints says that
  ``authenticate_token`` must return ``None`` for an expired or revoked token.
  The endpoints do not check it.
- The OAuth 1 temporary credentials response sets ``oauth_callback_confirmed``
  to ``true`` instead of ``True``, per RFC 5849 §2.1.
- The OAuth 2 web clients no longer pass the ``server_metadata_url`` document
  to the Requests or HTTPX client. A key such as ``hooks``, ``verify`` or
  ``scope`` in this document used to change the client settings, or to break
  every request. :issue:`1017`
- The async OAuth 2 web clients use the ``redirect_uri`` of ``client_kwargs``
  when ``create_authorization_url`` gets none. They used to send no
  ``redirect_uri``.
- The OAuth 1.0a base string URI excludes the default port for IPv6 hosts,
  per :rfc:`5849#section-3.4.1.2`. :issue:`1027`
- ``JWTBearerTokenGenerator`` uses the ``expires_in`` given to ``generate``
  for the ``exp`` claim. The JWT used to keep the default lifetime, while the
  response announced the given one.
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
