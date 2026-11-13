Fixed
~~~~~

- The ``form_post`` page works under a Content Security Policy that restricts scripts.
  It shows a "Continue" button when the browser blocks its script.
  The script can be allowed by its hash, see :ref:`specs/form_post`.
