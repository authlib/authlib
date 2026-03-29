.. _flask_oauth2_server:

Flask Integration
=================

.. meta::
    :description: How to create an OAuth 2.0 provider in Flask with Authlib.
        And understand how OAuth 2.0 works. Authlib has all built-in grant
        types for you.

This section is not a step by step guide on how to create an OAuth 2.0 provider
in Flask. Instead, we will learn how the Flask implementation works, and some
technical details in an OAuth 2.0 provider.

If you need a quick example, here are the official tutorial guide and examples
on GitHub:

1. `Example of OAuth 2.0 server <https://github.com/authlib/example-oauth2-server>`_
2. `Example of OpenID Connect server <https://github.com/authlib/example-oidc-server>`_
3. `On Demand Demo for your business <https://authlib.org/support#on-demand-demo>`_

At the very beginning, we need to have some basic understanding of
:ref:`the OAuth 2.0 <intro_oauth2>`.

.. important::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Looking for Flask OAuth 2.0 client? Check out :ref:`flask_client`.
Looking for Flask OAuth 2.0 resource server? Check out :ref:`flask_oauth2_resource_protector`.

.. toctree::
    :maxdepth: 2

    authorization-server
    grants
    endpoints
    openid-connect
    api
