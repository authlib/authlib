Security
~~~~~~~~

- The OpenID Connect implicit and hybrid grants refuse ``response_mode=form_post``
  when the redirect URI does not use the ``http`` or ``https`` scheme. They
  return an ``invalid_request`` error and do not redirect. A client with a
  ``javascript:`` redirect URI could run a script in the origin of the
  authorization server, even when the user denied the authorization.
  `GHSA-gp2m-377p-m4j3 <https://github.com/authlib/authlib/security/advisories/GHSA-gp2m-377p-m4j3>`_
