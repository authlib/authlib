.. _starlette_oauth1_client:

Starlette Integration
=====================

.. meta::
    :description: The built-in Starlette integrations for OAuth 1.0
        clients, powered by Authlib.

.. module:: authlib.integrations.starlette_client
    :noindex:

Starlette_ is a lightweight ASGI framework/toolkit, which is ideal for
building high performance asyncio services.

.. _Starlette: https://www.starlette.io/

This documentation covers OAuth 1.0 Client support for Starlette. Because all
the frameworks integrations share the same API, it is best to:

Read :ref:`frameworks_oauth1_clients` at first.

The difference between Starlette and Flask/Django integrations is Starlette
is **async**. We will use ``await`` for the functions we need to call. But
first, let's create an :class:`OAuth` instance::

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()

Unlike Flask and Django, Starlette OAuth registry uses HTTPX
:class:`~authlib.integrations.httpx_client.AsyncOAuth1Client` as the OAuth 1.0
backend.


Enable Session for OAuth 1.0
-----------------------------

With OAuth 1.0, we need to use a temporary credential to exchange for an access
token. This temporary credential is created before redirecting to the provider
(Twitter), and needs to be saved somewhere in order to use it later.

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

Just like the examples in :ref:`frameworks_oauth1_clients`, but Starlette is
**async**, the routes for authorization should look like::

    @app.route('/login/twitter')
    async def login_via_twitter(request):
        twitter = oauth.create_client('twitter')
        redirect_uri = request.url_for('authorize_twitter')
        return await twitter.authorize_redirect(request, redirect_uri)

    @app.route('/auth/twitter')
    async def authorize_twitter(request):
        twitter = oauth.create_client('twitter')
        token = await twitter.authorize_access_token(request)
        resp = await twitter.get('account/verify_credentials.json')
        profile = resp.json()
        # do something with the token and profile
        return '...'

Examples
--------

We have Starlette demos at https://github.com/authlib/demo-oauth-client

1. OAuth 1.0: `Starlette Twitter login <https://github.com/authlib/demo-oauth-client/tree/master/starlette-twitter-login>`_
