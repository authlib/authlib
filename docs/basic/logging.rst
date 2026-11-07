Logging
=======

You can always enable debug logging when you run into issues in your code:

.. code-block:: python

  import logging
  import sys
  log = logging.getLogger('authlib')
  log.addHandler(logging.StreamHandler(sys.stdout))
  log.setLevel(logging.DEBUG)

.. warning::

    At the ``DEBUG`` level, Authlib logs secrets, such as the issued tokens
    and the PKCE code verifiers. Do not enable it in production.
