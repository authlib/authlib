Added
~~~~~

- ``grant.interactions`` lists the interactions the user must go through
  before the authorization response, in order. The OpenID Connect grants add
  ``"login"``, ``"consent"`` and ``"select_account"``. ``grant.prompt`` is the
  first of them.

Changed
~~~~~~~

- ``get_consent_grant`` calls the new ``validate_interactions`` method of the
  grant after ``validate_consent_request``. With ``prompt=none``, the OpenID
  Connect errors such as ``login_required`` are raised there. If you override
  ``get_consent_grant``, call it too.

Deprecated
~~~~~~~~~~

- Setting ``grant.prompt`` is deprecated. It only changes the value that
  ``grant.prompt`` returns. Read ``grant.interactions`` instead.
