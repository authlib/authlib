.. _django_oauth2_server:

Django Integration
==================

.. meta::
    :description: How to create an OAuth 2.0 provider in Django with Authlib.
        And understand how OAuth 2.0 works. Authlib has all built-in grant
        types for you.

.. versionadded:: v0.12

This section is not a step by step guide on how to create an OAuth 2.0 provider
in Django. Instead, we will learn how the Django implementation works, and some
technical details in an OAuth 2.0 provider.

At the very beginning, we need to have some basic understanding of
:ref:`the OAuth 2.0 <intro_oauth2>`.

.. important::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Looking for Django OAuth 2.0 client? Check out :ref:`django_client`.
Looking for Django OAuth 2.0 resource server? Check out :ref:`django_resource_server`.

.. toctree::
    :maxdepth: 2

    authorization-server
    grants
    endpoints
    openid-connect
    api
