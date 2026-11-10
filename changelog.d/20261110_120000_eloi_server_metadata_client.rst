Fixed
~~~~~

- The OAuth 2 web clients no longer pass the ``server_metadata_url`` document
  to the requests or httpx client. Only its ``token_endpoint`` is used. A key
  such as ``hooks``, ``verify``, ``client_id`` or ``scope`` in this document
  used to change the client settings, or to break every request.
  :issue:`1017`
