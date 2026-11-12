Fixed
~~~~~

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
