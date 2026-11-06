Fixed
~~~~~

- ``PrivateKeyJWT`` accepts an EC or OKP private key as a PEM string or a JWK
  dict. The key type follows ``alg``. It used to import every key as an RSA
  key.
- JWT assertions signed by authlib carry the ``kid`` of the key, unless the
  header sets one (OpenID Connect Core §10.1). This covers ``PrivateKeyJWT``,
  ``ClientSecretJWT``, JWT bearer grants and ID-JAG. Servers can then find the
  right key when the signer has several keys.
- Signing a JWT assertion no longer adds ``alg`` to the ``headers`` dict given
  by the caller.
