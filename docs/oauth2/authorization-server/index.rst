.. _authorization_server:

Authorization Server
====================

An Authorization Server is the component that authenticates users and issues
access tokens to clients. Build this when you want to run your own OAuth 2.0
or OpenID Connect provider.

Not sure this is the right role? See :ref:`intro_oauth2` for an overview of
all OAuth 2.0 roles.

Looking for the :ref:`resource_server` (protecting an API)?
Or the :ref:`oauth_client` (consuming an OAuth provider)?

Understand
----------

Before implementing, read the concept guides:

* :ref:`intro_oauth2` — OAuth 2.0 roles, flows, and grant types

How-to
------

OAuth 2.0
~~~~~~~~~

.. toctree::
    :maxdepth: 2

    flask/index
    django/index

Reference
---------

Relevant specifications:

* :doc:`../specs/rfc6749` — The OAuth 2.0 Authorization Framework
* :doc:`../specs/rfc7636` — PKCE
* :doc:`../specs/rfc7591` — Dynamic Client Registration
* :doc:`../specs/rfc8414` — Authorization Server Metadata
* :doc:`../specs/oidc` — OpenID Connect Core
