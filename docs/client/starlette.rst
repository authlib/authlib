.. _starlette_client:

Starlette OAuth Client
======================

.. meta::
    :description: The built-in Starlette integrations for OAuth 1.0, OAuth 2.0
        and OpenID Connect clients, powered by Authlib.

.. module:: authlib.integrations.starlette_client
    :noindex:

Starlette_ is a lightweight ASGI framework/toolkit, which is ideal for
building high performance asyncio services.

.. _Starlette: https://www.starlette.io/

This documentation covers OAuth 1.0, OAuth 2.0 and OpenID Connect Client
support for Starlette. Because all the frameworks integrations share the
same API, it is best to:

Read :ref:`frameworks_clients` at first.

The difference between Starlette and Flask/Django integrations is Starlette
is **async**. We will use ``await`` for the functions we need to call. But
first, let's create an :class:`OAuth` instance::

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

Register Remote Apps
--------------------

``oauth.register`` is the same as :ref:`frameworks_clients`::

    oauth.register(
        'google',
        client_id='...',
        client_secret='...',
        ...
    )

However, unlike Flask/Django, Starlette OAuth registry is using HTTPX
:class:`~authlib.integrations.httpx_client.AsyncOAuth1Client` and
:class:`~authlib.integrations.httpx_client.AsyncOAuth2Client` as the OAuth
backends. While Flask and Django are using the Requests version of
:class:`~authlib.integrations.requests_client.OAuth1Session` and
:class:`~authlib.integrations.requests_client.OAuth2Session`.


Enable Session for OAuth 1.0
----------------------------

With OAuth 1.0, we need to use a temporary credential to exchange for an access token.
This temporary credential is created before redirecting to the provider (Twitter),
and needs to be saved somewhere in order to use it later.

With OAuth 1, the Starlette client will save the request token in sessions. To
enable this, we need to add the ``SessionMiddleware`` middleware to the
application, which requires the installation of the ``itsdangerous`` package::

    from starlette.applications import Starlette
    from starlette.middleware.sessions import SessionMiddleware

    app = Starlette()
    app.add_middleware(SessionMiddleware, secret_key="some-random-string")

However, using the ``SessionMiddleware`` will store the temporary credential as
a secure cookie which will expose your request token to the client.

Routes for Authorization
------------------------

Just like the examples in :ref:`frameworks_clients`, but Starlette is **async**,
the routes for authorization should look like::

    @app.route('/login/google')
    async def login_via_google(request):
        google = oauth.create_client('google')
        redirect_uri = request.url_for('authorize_google')
        return await google.authorize_redirect(request, redirect_uri)

    @app.route('/auth/google')
    async def authorize_google(request):
        google = oauth.create_client('google')
        token = await google.authorize_access_token(request)
        # do something with the token and userinfo
        return '...'

Starlette OpenID Connect
------------------------

An OpenID Connect client is no different than a normal OAuth 2.0 client, just add
``openid`` scope when ``.register``. The built-in Starlette OAuth client will handle
everything automatically::

    oauth.register(
        'google',
        ...
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid profile email'}
    )

When we get the returned token::

    token = await oauth.google.authorize_access_token()

There should be a ``id_token`` in the response. Authlib has called `.parse_id_token`
automatically, we can get ``userinfo`` in the ``token``::

    userinfo = token['userinfo']

Examples
--------

We have Starlette demos at https://github.com/authlib/demo-oauth-client

1. OAuth 1.0: `Starlette Twitter login <https://github.com/authlib/demo-oauth-client/tree/master/starlette-twitter-login>`_
2. OAuth 2.0: `Starlette Google login <https://github.com/authlib/demo-oauth-client/tree/master/starlette-google-login>`_
