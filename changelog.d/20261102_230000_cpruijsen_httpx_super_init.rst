Fixed
~~~~~

- The HTTPX clients no longer raise a ``TypeError`` when an instrumentation
  library, such as ``opentelemetry-instrumentation-httpx`` or
  ``aws-xray-sdk``, has patched the httpx client classes. :issue:`557`
