Added
~~~~~

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

Changed
~~~~~~~

- When the request asks for several interactions, ``grant.prompt`` follows the
  new order. For instance, with ``prompt=consent select_account``, it is
  ``"select_account"`` instead of ``"consent"``.
- ``get_consent_grant`` calls the new ``validate_interactions`` method of the
  grant after ``validate_consent_request``. With ``prompt=none``, the
  ``consent_required`` and ``account_selection_required`` errors are raised
  there. If you override ``get_consent_grant``, call it too.

Deprecated
~~~~~~~~~~

- Setting ``grant.prompt`` is deprecated. It only changes the value that
  ``grant.prompt`` returns. Read ``grant.interactions`` instead.
