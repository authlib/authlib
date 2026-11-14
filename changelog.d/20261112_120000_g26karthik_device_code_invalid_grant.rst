Breaking changes
~~~~~~~~~~~~~~~~

- ``DeviceCodeGrant`` responds with ``invalid_grant`` to an unknown
  ``device_code`` or to one issued to another client, per
  :rfc:`6749#section-5.2`. It used to respond with ``invalid_request`` and
  ``unauthorized_client``.
