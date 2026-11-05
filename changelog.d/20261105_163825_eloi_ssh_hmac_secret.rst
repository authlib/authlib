Security
~~~~~~~~

- ``authlib.jose`` refuses as an HMAC secret every OpenSSH public key or
  certificate that it can load as an RSA, EC or OKP key. It used to accept a
  key with a tab after the key type, and certificates. These keys verify
  ``RS256`` and ``EdDSA`` tokens, so anyone who knew the public key could
  forge an ``HS256`` token for an application that did not restrict the
  algorithms. This completes the fix for CVE-2026-114615.
  `GHSA-f7j6-p4qx-gq99 <https://github.com/authlib/authlib/security/advisories/GHSA-f7j6-p4qx-gq99>`_
