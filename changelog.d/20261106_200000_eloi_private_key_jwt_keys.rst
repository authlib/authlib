Fixed
~~~~~

- ``PrivateKeyJWT`` accepts an EC or OKP private key as a PEM string or a JWK
  dict. It used to import every key as an RSA key. :pr:`1018`
- The JWT assertions signed by Authlib carry the ``kid`` of the key, unless the
  header sets one, per OpenID Connect Core §10.1. This covers
  ``PrivateKeyJWT``, ``ClientSecretJWT``, the JWT bearer grants and ID-JAG.
  :pr:`1018`
- Signing a JWT assertion no longer adds ``alg`` to the ``headers`` dict of
  the caller. :pr:`1018`
