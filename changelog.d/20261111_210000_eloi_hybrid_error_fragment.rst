Fixed
~~~~~

- The hybrid flow redirects its errors in the fragment instead of the query,
  for a missing ``nonce``, an unsupported scope and an unauthorized
  ``response_type``.
