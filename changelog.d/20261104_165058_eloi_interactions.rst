Breaking changes
~~~~~~~~~~~~~~~~

- ``get_consent_grant`` calls the new ``validate_interactions`` method of the
  grant. Overrides of ``get_consent_grant`` must call it too. :issue:`740`
- When the request asks for several interactions, ``grant.prompt`` follows the
  order of ``grant.interactions``. For instance, with
  ``prompt=consent select_account``, it is ``"select_account"`` instead of
  ``"consent"``. :issue:`740`

Added
~~~~~

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

Deprecated
~~~~~~~~~~

- Setting ``grant.prompt`` is deprecated. Read ``grant.interactions``
  instead. :issue:`740`
