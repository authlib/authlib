.. _flask_oauth1_client:

Flask Integration
=================

.. meta::
    :description: The built-in Flask integrations for OAuth 1.0
        clients, powered by Authlib.

.. module:: authlib.integrations.flask_client
    :noindex:

This documentation covers OAuth 1.0 Client support for Flask. Looking for
OAuth 1.0 provider?

- :ref:`flask_oauth1_server`

Flask OAuth client can handle OAuth 1 services. It shares a similar API with
Flask-OAuthlib, you can transfer your code from Flask-OAuthlib to Authlib with
ease.

Create a registry with :class:`OAuth` object::

    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)

You can also initialize it later with :meth:`~OAuth.init_app` method::

    oauth = OAuth()
    oauth.init_app(app)

.. important::

    Please read :ref:`frameworks_oauth1_clients` at first. Authlib has a shared
    API design among framework integrations, learn them from
    :ref:`frameworks_oauth1_clients`.

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
EXAMPLE_REQUEST_TOKEN_URL  URL to fetch OAuth request token
========================== ===============================

Here is a full list of the configuration keys:

- ``{name}_CLIENT_ID``: Client key of OAuth 1
- ``{name}_CLIENT_SECRET``: Client secret of OAuth 1
- ``{name}_REQUEST_TOKEN_URL``: Request Token endpoint for OAuth 1
- ``{name}_REQUEST_TOKEN_PARAMS``: Extra parameters for Request Token endpoint
- ``{name}_ACCESS_TOKEN_URL``: Access Token endpoint for OAuth 1
- ``{name}_ACCESS_TOKEN_PARAMS``: Extra parameters for Access Token endpoint
- ``{name}_AUTHORIZE_URL``: Endpoint for user authorization of OAuth 1
- ``{name}_AUTHORIZE_PARAMS``: Extra parameters for Authorization Endpoint.
- ``{name}_API_BASE_URL``: A base URL endpoint to make requests simple
- ``{name}_CLIENT_KWARGS``: Extra keyword arguments for OAuth1Session


Using Cache for Temporary Credential
-------------------------------------

By default, the Flask OAuth registry will use Flask session to store OAuth 1.0
temporary credential (request token). However, in this way, there are chances
your temporary credential will be exposed.

Our ``OAuth`` registry provides a simple way to store temporary credentials in a
cache system. When initializing ``OAuth``, you can pass an ``cache`` instance::

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
            self.app = app

        def delete(self, key: str) -> None:
            pass

        def get(self, key: str) -> str | None:
            pass

        def set(self, key: str, value: str, expires: int | None = None) -> None:
            pass


Routes for Authorization
------------------------

Unlike the examples in :ref:`frameworks_oauth1_clients`, Flask does not pass a
``request`` into routes. In this case, the routes for authorization should look
like::

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

    @app.route('/twitter')
    def show_twitter_timeline():
        resp = oauth.twitter.get('statuses/user_timeline.json')
        resp.raise_for_status()
        tweets = resp.json()
        return render_template('twitter.html', tweets=tweets)

In this case, our ``fetch_token`` could look like::

    from your_project import current_user

    def fetch_token(name):
        token = OAuth1Token.find(
            name=name,
            user=current_user,
        )
        return token.to_token()

    # initialize the OAuth registry with this fetch_token function
    oauth = OAuth(fetch_token=fetch_token)

You don't have to pass ``token``, you don't have to pass ``request``. That
is the fantasy of Flask.

Examples
---------

Here are some example projects for you to learn Flask OAuth 1.0 client integrations:

1. `Flask Twitter Login`_.

.. _`Flask Twitter Login`: https://github.com/authlib/demo-oauth-client/tree/master/flask-twitter-tool
