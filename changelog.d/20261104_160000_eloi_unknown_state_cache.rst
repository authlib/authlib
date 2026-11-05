Fixed
~~~~~

- With a ``cache``, the Flask, Django and Starlette clients refuse an unknown
  ``state`` with ``MismatchingStateError``. They no longer pass it to the
  cache, whose backend could reject it with an unhandled error.
