Added
~~~~~

- The Requests clients accept ``headers``, sent with every request of the
  session, like the HTTPX clients. With the web clients,
  ``client_kwargs={"headers": ...}`` also applies to the
  ``server_metadata_url`` and ``jwks_uri`` requests. :issue:`633`
