Fixed
~~~~~

- The size limits of ``authlib.jose`` raise ``ExceededSizeError``, a
  ``JoseError``, so an application that catches ``JoseError`` refuses a too
  long token instead of failing. It is also a ``ValueError``, as before.
