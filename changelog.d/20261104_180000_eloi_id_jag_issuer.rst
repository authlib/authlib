Security
~~~~~~~~

- ``IDJAGGrant`` stores the verified claims of the ID-JAG in
  ``request.id_jag_claims``. ``authenticate_user`` can use them to resolve
  the user with the ``iss`` and ``sub`` claims, and ``tenant`` for a
  multi-tenant IdP. The documentation used to resolve the user with ``sub``
  alone. An IdP, or a tenant of an IdP, could then get access tokens for the
  users of another one. Update ``authenticate_user`` if your server trusts
  several IdPs or a multi-tenant IdP.
  `GHSA-9qr6-8289-9j56 <https://github.com/authlib/authlib/security/advisories/GHSA-9qr6-8289-9j56>`_
