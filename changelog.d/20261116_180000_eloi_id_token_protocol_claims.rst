Fixed
~~~~~

- The claims returned by ``generate_user_info`` no longer replace the claims
  that the server sets in the ID token, such as ``iss``, ``aud``, ``nonce``,
  ``auth_time``, ``at_hash`` and ``c_hash``. To change ``iss`` or ``aud``,
  use ``get_client_claims``.
