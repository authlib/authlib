Added
~~~~~

- The requests clients accept ``headers``, like the httpx clients. These
  headers are sent with every request of the session. With the web framework
  integrations, ``client_kwargs={"headers": ...}`` also sends them with the
  ``server_metadata_url`` and ``jwks_uri`` requests. Before, a ``headers``
  value given to the requests clients was ignored. :issue:`633`
