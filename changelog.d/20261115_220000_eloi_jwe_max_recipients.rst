Security
~~~~~~~~

- ``JsonWebEncryption.deserialize_json()`` rejects a JWE JSON Serialization
  with more than 16 recipients. Set ``JsonWebEncryption.MAX_RECIPIENTS`` to
  change the limit. A message with many recipients used to cost one
  private-key operation per recipient.
  `GHSA-8cj9-p42v-64gg <https://github.com/authlib/authlib/security/advisories/GHSA-8cj9-p42v-64gg>`_
