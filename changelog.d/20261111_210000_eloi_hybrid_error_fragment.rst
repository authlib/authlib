Fixed
~~~~~

- The hybrid flow redirects its errors in the fragment instead of the query,
  for a missing ``nonce``, an unsupported scope and an unauthorized
  ``response_type``. ``exists_nonce`` is no longer called one more time at
  each validation of the request.
