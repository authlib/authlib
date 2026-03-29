.. _flask_oauth1_server:

Flask Integration
=================

.. meta::
    :description: How to create an OAuth 1.0 server in Flask with Authlib.
        And understand how OAuth 1.0 works.

Implement OAuth 1.0 provider in Flask. An OAuth 1 provider contains two servers:

- Authorization Server: to issue access tokens
- Resources Server: to serve your users' resources

At the very beginning, we need to have some basic understanding of
:ref:`the OAuth 1.0 <intro_oauth1>`.

.. important::

    If you are developing on your localhost, remember to set the environment
    variable::

        export AUTHLIB_INSECURE_TRANSPORT=true

Looking for Flask OAuth 1.0 client? Check out :ref:`flask_oauth1_client`.

.. toctree::
    :maxdepth: 2

    authorization-server
    resource-server
    customize
    api
