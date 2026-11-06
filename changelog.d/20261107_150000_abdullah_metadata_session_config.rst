Fixed
~~~~~

- The OAuth 2 web clients ignore the HTTP client settings in a fetched
  ``server_metadata_url`` document, such as ``hooks``, ``verify`` or
  ``proxies``. They used to apply them to the requests or httpx client, so an
  unexpected key could break every request. :issue:`1017`
