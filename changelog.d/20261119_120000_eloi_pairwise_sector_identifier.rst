Fixed
~~~~~

- The OpenID Connect registration rejects a ``pairwise`` client whose
  ``redirect_uris`` have several hosts and that has no
  ``sector_identifier_uri``, per OpenID Connect Core §8.1.
