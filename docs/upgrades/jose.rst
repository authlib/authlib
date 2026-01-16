1.7: Upgrade to joserfc
=======================

joserfc_ is derived from Authlib and provides a cleaner design along with
first-class type hints. We strongly recommend using ``joserfc`` instead of
the ``authlib.jose`` module.

Starting with **Authlib 1.7.0**, the ``authlib.jose`` module is deprecated and
will emit deprecation warnings. A comprehensive
`Migrating from Authlib <https://jose.authlib.org/en/migrations/authlib/>`_
guide is available in the joserfc_ documentation to help you transition.

.. _joserfc: https://jose.authlib.org/en/

The following modules are affected by this upgrade:

- ``authlib.oauth2.rfc7523``
- ``authlib.oauth2.rfc7591``
- ``authlib.oauth2.rfc7592``
- ``authlib.oauth2.rfc9068``
- ``authlib.oauth2.rfc9101``
- ``authlib.oidc.core``

Breaking Changes
----------------

A common breaking change involves the exceptions raised by the affected modules.
Since these modules now use ``joserfc``, all exceptions are ``joserfc``-based.
If your code previously caught exceptions from ``authlib.jose``, you should
update it to catch the corresponding exceptions from ``joserfc`` instead.

.. code-block:: diff

    -from authlib.jose.errors import JoseError
    +from joserfc.errors import JoseError

     try:
         do_something()
     except JoseError:
         pass

Deprecated Messages
-------------------
