Added
~~~~~

- Add support for signed UserInfo responses in the OpenID Connect client, as
  defined in `Section 5.3.2 of the OpenID Connect Core specification`_. When
  the provider returns the UserInfo Claims as a JWT with
  ``Content-Type: application/jwt``, ``userinfo()`` decodes the JWT with the
  provider's JWK Set (the same trust path as ``parse_id_token``, including a
  forced JWK Set refresh on key rotation) and validates that the signed
  response carries the ``sub``, ``iss`` and ``aud`` Claims required by
  Section 5.3.2, instead of failing with a ``JSONDecodeError``. Encrypted
  UserInfo responses are not supported yet. :issue:`941`

.. _`Section 5.3.2 of the OpenID Connect Core specification`: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
