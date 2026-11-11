Added
~~~~~

- ``authlib.oauth2.multiple_response_types.MultipleResponseTypes`` implements
  OAuth 2.0 Multiple Response Type Encoding Practices. Clients choose the
  response mode of any authorization grant with the ``response_mode``
  parameter, and errors use it too. The server accepts the modes of its
  ``response_modes_supported`` metadata, and never sends access tokens or ID
  Tokens in the query.

Deprecated
~~~~~~~~~~

- Using ``response_mode`` with the OpenID Connect implicit and hybrid grants
  without the ``MultipleResponseTypes`` extension is deprecated. Register it
  with ``server.register_extension(MultipleResponseTypes())``. It will stop
  working in version 1.11.
