Security
~~~~~~~~

- The OAuth 1.0 server rejects HMAC-SHA1 and PLAINTEXT signatures from a
  client without a client secret. Anyone could compute these signatures, and
  impersonate a client registered with an RSA key only.
  `GHSA-4gjv-v7fq-ghfp <https://github.com/authlib/authlib/security/advisories/GHSA-4gjv-v7fq-ghfp>`_
