Added
~~~~~

- ``AuthorizationCodeGrant.revoke_authorization_code_tokens(code, client)`` is
  called when a code is not found, before the request is denied. Implement it
  to revoke the tokens issued with a reused code, per RFC 6749 §4.1.2. The
  documentation shows how to link the tokens to their code. :issue:`757`
