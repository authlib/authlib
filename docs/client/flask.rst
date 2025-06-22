.. _flask_client:

Flask OAuth Client
==================

.. meta::
    :description: The built-in Flask integrations for OAuth 1.0, OAuth 2.0
        and OpenID Connect clients, powered by Authlib.


.. module:: authlib.integrations.flask_client
    :noindex:

This documentation covers OAuth 1.0, OAuth 2.0 and OpenID Connect Client
support for Flask. Looking for OAuth providers?

- :ref:`flask_oauth1_server`
- :ref:`flask_oauth2_server`

Flask OAuth client can handle OAuth 1 and OAuth 2 services. It shares a
similar API with Flask-OAuthlib, you can transfer your code from
Flask-OAuthlib to Authlib with ease.

Create a registry with :class:`OAuth` object::

    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)

You can also initialize it later with :meth:`~OAuth.init_app` method::

    oauth = OAuth()
    oauth.init_app(app)

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

.. important::

    Please read :ref:`frameworks_clients` at first. Authlib has a shared API
    design among framework integrations, learn them from :ref:`frameworks_clients`.

Configuration
-------------

Authlib Flask OAuth registry can load the configuration from Flask ``app.config``
automatically. Every key-value pair in ``.register`` can be omitted. They can be
configured in your Flask App configuration. Config keys are formatted as
``{name}_{key}`` in uppercase, e.g.

========================== ================================
TWITTER_CLIENT_ID          Twitter Consumer Key
TWITTER_CLIENT_SECRET      Twitter Consumer Secret
TWITTER_REQUEST_TOKEN_URL  URL to fetch OAuth request token
========================== ================================

If you register your remote app as ``oauth.register('example', ...)``, the
config keys would look like:

========================== ===============================
EXAMPLE_CLIENT_ID          OAuth Consumer Key
EXAMPLE_CLIENT_SECRET      OAuth Consumer Secret
EXAMPLE_ACCESS_TOKEN_URL   URL to fetch OAuth access token
========================== ===============================

Here is a full list of the configuration keys:

- ``{name}_CLIENT_ID``: Client key of OAuth 1, or Client ID of OAuth 2
- ``{name}_CLIENT_SECRET``: Client secret of OAuth 2, or Client Secret of OAuth 2
- ``{name}_REQUEST_TOKEN_URL``: Request Token endpoint for OAuth 1
- ``{name}_REQUEST_TOKEN_PARAMS``: Extra parameters for Request Token endpoint
- ``{name}_ACCESS_TOKEN_URL``: Access Token endpoint for OAuth 1 and OAuth 2
- ``{name}_ACCESS_TOKEN_PARAMS``: Extra parameters for Access Token endpoint
- ``{name}_AUTHORIZE_URL``: Endpoint for user authorization of OAuth 1 or OAuth 2
- ``{name}_AUTHORIZE_PARAMS``: Extra parameters for Authorization Endpoint.
- ``{name}_API_BASE_URL``: A base URL endpoint to make requests simple
- ``{name}_CLIENT_KWARGS``: Extra keyword arguments for OAuth1Session or OAuth2Session


We suggest that you keep ONLY ``{name}_CLIENT_ID`` and ``{name}_CLIENT_SECRET`` in
your Flask application configuration.

Using Cache for Temporary Credential
------------------------------------

By default, the Flask OAuth registry will use Flask session to store OAuth 1.0 temporary
credential (request token). However, in this way, there are chances your temporary
credential will be exposed.

Our ``OAuth`` registry provides a simple way to store temporary credentials in a cache
system. When initializing ``OAuth``, you can pass an ``cache`` instance::

    oauth = OAuth(app, cache=cache)

    # or initialize lazily
    oauth = OAuth()
    oauth.init_app(app, cache=cache)

A ``cache`` instance MUST have methods:

- ``.delete(key)``
- ``.get(key)``
- ``.set(key, value, expires=None)``

An example of a ``cache`` instance can be:

.. code-block:: python

    from flask import Flask

    class OAuthCache:

        def __init__(self, app: Flask) -> None:
            """Initialize the AuthCache."""
            self.app = app

        def delete(self, key: str) -> None:
            """
            Delete a cache entry.
    
            :param key: Unique identifier for the cache entry.
            """

        def get(self, key: str) -> str | None:
            """
            Retrieve a value from the cache.
    
            :param key: Unique identifier for the cache entry.
            :return: Retrieved value or None if not found or expired.
            """

        def set(self, key: str, value: str, expires: int | None = None) -> None:
            """
            Set a value in the cache with optional expiration.
    
            :param key: Unique identifier for the cache entry.
            :param value: Value to be stored.
            :param expires: Expiration time in seconds. Defaults to None (no expiration).
            """


Routes for Authorization
------------------------

Unlike the examples in :ref:`frameworks_clients`, Flask does not pass a ``request``
into routes. In this case, the routes for authorization should look like::

    from flask import url_for, redirect

    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.twitter.authorize_redirect(redirect_uri)

    @app.route('/authorize')
    def authorize():
        token = oauth.twitter.authorize_access_token()
        resp = oauth.twitter.get('account/verify_credentials.json')
        resp.raise_for_status()
        profile = resp.json()
        # do something with the token and profile
        return redirect('/')

Accessing OAuth Resources
-------------------------

There is no ``request`` in accessing OAuth resources either. Just like above,
we don't need to pass the ``request`` parameter, everything is handled by Authlib
automatically::

    from flask import render_template

    @app.route('/github')
    def show_github_profile():
        resp = oauth.github.get('user')
        resp.raise_for_status()
        profile = resp.json()
        return render_template('github.html', profile=profile)

In this case, our ``fetch_token`` could look like::

    from your_project import current_user

    def fetch_token(name):
        if name in OAUTH1_SERVICES:
            model = OAuth1Token
        else:
            model = OAuth2Token

        token = model.find(
            name=name,
            user=current_user,
        )
        return token.to_token()

    # initialize the OAuth registry with this fetch_token function
    oauth = OAuth(fetch_token=fetch_token)

You don't have to pass ``token``, you don't have to pass ``request``. That
is the fantasy of Flask.

Auto Update Token via Signal
----------------------------

.. versionadded:: v0.13

    The signal is added since v0.13

Instead of defining an ``update_token`` method and passing it into the OAuth registry,
it is also possible to use a signal to listen for token updating.

Before using the signal, make sure you have installed the **blinker** library::

    $ pip install blinker

Connect the ``token_update`` signal::

    from authlib.integrations.flask_client import token_update

    @token_update.connect_via(app)
    def on_token_update(sender, name, token, refresh_token=None, access_token=None):
        if refresh_token:
            item = OAuth2Token.find(name=name, refresh_token=refresh_token)
        elif access_token:
            item = OAuth2Token.find(name=name, access_token=access_token)
        else:
            return

        # update old token
        item.access_token = token['access_token']
        item.refresh_token = token.get('refresh_token')
        item.expires_at = token['expires_at']
        item.save()


Flask OpenID Connect Client
---------------------------

An OpenID Connect client is no different than a normal OAuth 2.0 client. When
registered with ``openid`` scope, the built-in Flask OAuth client will handle everything
automatically::

    oauth.register(
        'google',
        ...
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid profile email'}
    )

When we get the returned token::

    token = oauth.google.authorize_access_token()

There should be a ``id_token`` in the response. Authlib has called `.parse_id_token`
automatically, we can get ``userinfo`` in the ``token``::

    userinfo = token['userinfo']

Examples
---------

Here are some example projects for you to learn Flask OAuth client integrations:

1. OAuth 1.0: `Flask Twitter Login`_.
2. OAuth 2.0 & OpenID Connect: `Flask Google Login`_.

.. _`Flask Twitter Login`: https://github.com/authlib/demo-oauth-client/tree/master/flask-twitter-tool
.. _`Flask Google Login`: https://github.com/authlib/demo-oauth-client/tree/master/flask-google-login
