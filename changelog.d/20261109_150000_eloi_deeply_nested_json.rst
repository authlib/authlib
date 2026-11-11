Fixed
~~~~~

- Client assertions, JWT bearer assertions and ID-JAG assertions with deeply
  nested JSON return an ``invalid_client`` or ``invalid_grant`` error instead
  of an HTTP 500 error. ``OAuth1Client`` raises a ``ValueError`` for such
  token responses.
