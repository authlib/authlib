Breaking changes
~~~~~~~~~~~~~~~~

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

Changed
~~~~~~~

- ``grant.interactions`` contains ``"login"`` when the user is not logged in,
  also without OpenID Connect.

Added
~~~~~

- ``AuthorizationSessionMixin.can_redirect_error`` tells if an error can be
  sent to the redirect URI of the client. Per :rfc:`9700#section-4.11.2`,
  return false for the redirect URIs you do not trust. The error is then
  returned without redirection. It also applies to ``access_denied``.
- ``grant.silent`` is true when the request must be done without any user
  interaction, such as with the OpenID Connect ``prompt=none``.

Fixed
~~~~~

- With a request object (:rfc:`9101`), the errors of
  ``create_authorization_response``, such as ``access_denied``, contain the
  ``state`` of the request object.
