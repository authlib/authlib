Fixed
~~~~~

- ``AuthorizationServerMetadata.validate()`` accepts an empty ``response_types_supported``.
  A server without an authorization endpoint can publish ``[]``, per :rfc:`8414#section-2`.
