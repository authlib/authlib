Added
~~~~~

- ``AuthorizationCodeGrant.revoke_authorization_code_tokens(code, client)`` is
  called when a code is not found, for instance when it is reused. Implement
  it to revoke the tokens issued with this code, per RFC 6749 §4.1.2.
  :issue:`757`
