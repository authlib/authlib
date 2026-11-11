.. _intro:

Introduction
============

.. meta::
    :description: A general introduction to Authlib, a project that powers from
        low-level specification implementation to high-level framework
        integrations.

Authlib is the ultimate Python library in building OAuth and OpenID Connect
clients and servers. It offers generic implementations of RFCs, including
OAuth 1.0, OAuth 2.0, JWT and many more. It becomes a :ref:`monolithic`
project that powers from low-level specification implementation to high-level
framework integrations.

I'm intended to make it profitable so that it can be :ref:`sustainable`, check
out the :ref:`funding` section.

.. _monolithic:

Monolithic
----------

Authlib is a monolithic library. While being monolithic, it keeps everything
synchronized, from spec implementation to framework integrations, from client
requests to service providers.

The benefits are obvious; it won't break things. When specifications changed,
implementation will change too. Let the developers of Authlib take the pain,
users of Authlib should not suffer from it.

You don't have to worry about monolithic, it doesn't cost your memory. If
you don't import a module, it won't be loaded. We don't madly import everything
into the root **__init__.py**.

Extendable
----------

Authlib is designed as flexible as possible. Since it is built from low-level
specification implementation to high-level framework integrations, if a high
level can't meet your needs, you can always create one for your purpose based on
the low-level implementation.

Most of the cases, you don't need to do so. Extendable has been taken
into account from the start of the project. Take OAuth 2.0 server as an
example, instead of a pre-configured server, Authlib takes advantage of
``register``.

.. invisible-code-block: python

    from authlib.oauth2.rfc7009 import RevocationEndpoint

.. code-block:: python

    authorization_server.register_grant(AuthorizationCodeGrant)
    authorization_server.register_endpoint(RevocationEndpoint)

If you find anything not that extendable, you can ask help on
`GitHub Discussions <https://github.com/authlib/authlib/discussions>`_ or open
an issue on GitHub.

Credits
-------

This project is inspired by:

* OAuthLib
* Flask-OAuthlib
* requests-oauthlib
* pyjwt
