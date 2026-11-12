Breaking changes
~~~~~~~~~~~~~~~~

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

Added
~~~~~

- ``AuthorizationSessionMixin.can_redirect_error`` tells if an error can be
  sent to the redirect URI of the client. Return false for the redirect URIs
  you do not trust, per :rfc:`9700#section-4.11.2`. The error, even
  ``access_denied``, is then returned without redirection. :pr:`1000`
- ``grant.silent`` is true when the request must be done without any user
  interaction, such as with the OpenID Connect ``prompt=none``. :pr:`1000`
- ``grant.interactions`` contains ``"login"`` when the user is not logged in,
  also without OpenID Connect. :pr:`1000`

Fixed
~~~~~

- With a request object (:rfc:`9101`), the errors of
  ``create_authorization_response``, such as ``access_denied``, contain the
  ``state`` of the request object. :pr:`1000`
