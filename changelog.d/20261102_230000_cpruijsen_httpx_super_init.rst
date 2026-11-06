Fixed
~~~~~

- The ``httpx`` client integrations initialize their transport base with
  ``super()``, so ``OAuth2Client``, ``AsyncOAuth2Client``,
  ``OAuth1Client``, ``AsyncOAuth1Client``, ``AssertionClient`` and
  ``AsyncAssertionClient`` no longer raise ``TypeError`` when an
  instrumentation library such as ``aws-xray-sdk`` or
  ``opentelemetry-instrumentation-httpx`` has patched the httpx client
  classes.
  :issue:`557` :pr:`953`
