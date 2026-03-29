.. _django_oauth1_client:

Django Integration
==================

.. meta::
    :description: The built-in Django integrations for OAuth 1.0
        clients, powered by Authlib.

.. module:: authlib.integrations.django_client
    :noindex:

Looking for OAuth 1.0 provider?

- :ref:`django_oauth1_server`

The Django client can handle OAuth 1 services. Authlib has a shared API design
among framework integrations. Get started with :ref:`frameworks_oauth1_clients`.

Create a registry with :class:`OAuth` object::

    from authlib.integrations.django_client import OAuth

    oauth = OAuth()

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter.

.. important::

    Please read :ref:`frameworks_oauth1_clients` at first. Authlib has a shared
    API design among framework integrations, learn them from
    :ref:`frameworks_oauth1_clients`.


Configuration
-------------

Authlib Django OAuth registry can load the configuration from your Django
application settings automatically. Every key value pair can be omitted.
They can be configured from your Django settings::

    AUTHLIB_OAUTH_CLIENTS = {
        'twitter': {
            'client_id': 'Twitter Consumer Key',
            'client_secret': 'Twitter Consumer Secret',
            'request_token_url': 'https://api.twitter.com/oauth/request_token',
            'request_token_params': None,
            'access_token_url': 'https://api.twitter.com/oauth/access_token',
            'access_token_params': None,
            'authorize_url': 'https://api.twitter.com/oauth/authenticate',
            'api_base_url': 'https://api.twitter.com/1.1/',
            'client_kwargs': None
        }
    }

There are differences between OAuth 1.0 and OAuth 2.0, please check the
parameters in ``.register`` in :ref:`frameworks_oauth1_clients`.

Saving Temporary Credential
---------------------------

In OAuth 1.0, we need to use a temporary credential to exchange access token,
this temporary credential was created before redirecting to the provider (Twitter),
we need to save this temporary credential somewhere in order to use it later.

In OAuth 1, Django client will save the request token in sessions. In this
case, you just need to configure Session Middleware in Django::

    MIDDLEWARE = [
        'django.contrib.sessions.middleware.SessionMiddleware'
    ]

Follow the official Django documentation to set a proper session. Either a
database backend or a cache backend would work well.

.. warning::

    Be aware, using secure cookie as session backend will expose your request
    token.

Routes for Authorization
------------------------

Just like the example in :ref:`frameworks_oauth1_clients`, everything is the same.
But there is a hint to create ``redirect_uri`` with ``request`` in Django::

    def login(request):
        # build a full authorize callback uri
        redirect_uri = request.build_absolute_uri('/authorize')
        return oauth.twitter.authorize_redirect(request, redirect_uri)
