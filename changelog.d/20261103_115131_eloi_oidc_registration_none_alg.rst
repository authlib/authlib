Fixed
~~~~~

- OpenID Connect dynamic client registration rejects the ``none``
  ``id_token_signed_response_alg`` when the ``response_types`` return an ID
  Token from the authorization endpoint, per OpenID Connect Dynamic Client
  Registration §2. The check used to read a ``response_type`` metadata that
  does not exist, so it never applied.
