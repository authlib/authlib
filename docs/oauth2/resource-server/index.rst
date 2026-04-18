.. _resource_server:

Resource Server
===============

A Resource Server is an API that accepts and validates access tokens to protect
resources. Build this when you want to secure your API endpoints so that only
authorized clients can access them.

A resource server can be separate from the authorization server — it only needs
to validate the tokens that the authorization server issued.

Not sure this is the right role? See :ref:`intro_oauth2` for an overview of
all OAuth 2.0 roles.

Looking for the :ref:`authorization_server` (issuing tokens)?
Or the :ref:`oauth_client` (consuming an OAuth provider)?

Understand
----------

* :ref:`intro_oauth2` — OAuth 2.0 roles and token validation
* :doc:`../specs/rfc6750` — Bearer Token Usage

How-to
------

.. toctree::
    :maxdepth: 2

    flask
    django

Reference
---------

* :doc:`../specs/rfc6750` — Bearer Token Usage
* :doc:`../specs/rfc7662` — Token Introspection
