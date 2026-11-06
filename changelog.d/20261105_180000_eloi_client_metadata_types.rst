Fixed
~~~~~

- Dynamic client registration refuses client metadata with an unexpected
  type, like a ``scope`` that is not a string or a ``default_acr_values`` that
  is not a list of strings, with an ``invalid_client_metadata`` error. It used
  to return a server error, or to register the invalid value. This covers the
  RFC 7591, OpenID Connect, RP-Initiated Logout and Back-Channel Logout
  metadata. A ``null`` value is ignored, so the default value applies. An
  ``http`` post logout redirect URI for a public client also gets
  ``invalid_client_metadata``, instead of a ``ValueError``.
