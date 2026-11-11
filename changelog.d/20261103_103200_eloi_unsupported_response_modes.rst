Breaking changes
~~~~~~~~~~~~~~~~

- The OpenID Connect implicit and hybrid flows only accept the ``fragment``
  and ``form_post`` response modes. Other values, ``query`` included, get an
  ``invalid_request`` error in the fragment, before the user consent. Per
  OAuth 2.0 Multiple Response Type Encoding Practices §3 and §5, these
  responses must not be sent in the query string. An unknown value used to
  raise a ``ValueError`` after the user consent.
