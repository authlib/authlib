Security
~~~~~~~~

- ``authlib.jose`` rejects an RSA private key without ``p``, ``q``, ``dp``,
  ``dq`` and ``qi``, including in a key set. Recovering them from ``d`` could
  use a lot of CPU with a crafted key. Export the key with all its members.
  `GHSA-7wgf-r6fq-5h3c <https://github.com/authlib/authlib/security/advisories/GHSA-7wgf-r6fq-5h3c>`_
