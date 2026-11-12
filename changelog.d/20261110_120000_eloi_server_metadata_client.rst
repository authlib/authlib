Fixed
~~~~~

- The OAuth 2 web clients no longer pass the ``server_metadata_url`` document
  to the Requests or HTTPX client. A key such as ``hooks``, ``verify`` or
  ``scope`` in this document used to change the client settings, or to break
  every request. :issue:`1017`
