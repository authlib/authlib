.. _flask_client:

Flask Integration
=================

.. meta::
    :description: The built-in Flask integrations for OAuth 2.0
        and OpenID Connect clients, powered by Authlib.


.. module:: authlib.integrations.flask_client
    :noindex:

This documentation covers OAuth 2.0 and OpenID Connect Client support for
Flask. Looking for OAuth 2.0 server?

- :ref:`flask_oauth2_server`

Flask OAuth client shares a similar API with Flask-OAuthlib, you can transfer
your code from Flask-OAuthlib to Authlib with ease.

Create a registry with :class:`OAuth` object:

.. code-block:: python

    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)

You can also initialize it later with :meth:`~OAuth.init_app` method:

.. code-block:: python

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
``{name}_{key}`` in uppercase. If you register your remote app as
``oauth.register('example', ...)``, the config keys would look like:

========================== ===============================
EXAMPLE_CLIENT_ID          OAuth Client ID
EXAMPLE_CLIENT_SECRET      OAuth Client Secret
EXAMPLE_ACCESS_TOKEN_URL   URL to fetch OAuth access token
========================== ===============================

Here is a full list of the configuration keys:

- ``{name}_CLIENT_ID``: Client key of OAuth 1, or Client ID of OAuth 2
- ``{name}_CLIENT_SECRET``: Client secret of OAuth 1, or Client Secret of OAuth 2
- ``{name}_REQUEST_TOKEN_URL``: Request Token endpoint for OAuth 1
- ``{name}_REQUEST_TOKEN_PARAMS``: Extra parameters for Request Token endpoint
- ``{name}_ACCESS_TOKEN_URL``: Access Token endpoint for OAuth 1 and OAuth 2
- ``{name}_ACCESS_TOKEN_PARAMS``: Extra parameters for Access Token endpoint
- ``{name}_REFRESH_TOKEN_URL``: Refresh Token endpoint for OAuth 2
- ``{name}_REFRESH_TOKEN_PARAMS``: Extra parameters for Refresh Token endpoint
- ``{name}_AUTHORIZE_URL``: Endpoint for user authorization of OAuth 1 or OAuth 2
- ``{name}_AUTHORIZE_PARAMS``: Extra parameters for Authorization Endpoint.
- ``{name}_API_BASE_URL``: A base URL endpoint to make requests simple
- ``{name}_CLIENT_KWARGS``: Extra keyword arguments for OAuth1Session or OAuth2Session
- ``{name}_SERVER_METADATA_URL``: URL of the OpenID Connect discovery or OAuth 2.0 server metadata document


We suggest that you keep ONLY ``{name}_CLIENT_ID`` and ``{name}_CLIENT_SECRET`` in
your Flask application configuration.

Routes for Authorization
------------------------

Unlike the examples in :ref:`frameworks_clients`, Flask does not pass a ``request``
into routes. In this case, the routes for authorization should look like:

.. code-block:: python

    from flask import url_for, redirect

    @app.route('/login')
    def login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.github.authorize_redirect(redirect_uri)

    @app.route('/authorize')
    def authorize():
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user')
        resp.raise_for_status()
        profile = resp.json()
        # do something with the token and profile
        return redirect('/')

Accessing OAuth Resources
-------------------------

There is no ``request`` in accessing OAuth resources either. Just like above,
we don't need to pass the ``request`` parameter, everything is handled by Authlib
automatically:

.. code-block:: python

    from flask import render_template

    @app.route('/github')
    def show_github_profile():
        resp = oauth.github.get('user')
        resp.raise_for_status()
        profile = resp.json()
        return render_template('github.html', profile=profile)

In this case, our ``fetch_token`` could look like:

.. skip: next "depends on the application models"

.. code-block:: python

    from your_project import current_user

    def fetch_token(name):
        token = OAuth2Token.find(
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


Instead of defining an ``update_token`` method and passing it into the OAuth registry,
it is also possible to use a signal to listen for token updating.

The signal requires the **blinker** library. Flask installs it since version 2.3.

Connect the ``token_update`` signal:

.. code-block:: python

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
automatically:

.. code-block:: python

    oauth.register(
        'google',
        client_id='Your Google client ID',
        client_secret='Your Google client secret',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid profile email'}
    )

When we get the returned token:

.. skip: next "fragment of the callback view"

.. code-block:: python

    token = oauth.google.authorize_access_token()

There should be a ``id_token`` in the response. Authlib has called `.parse_id_token`
automatically, we can get ``userinfo`` in the ``token``:

.. skip: next "fragment of the callback view"

.. code-block:: python

    userinfo = token['userinfo']

When the authorization request includes a nonce, the ID Token must contain the
same nonce. An ID Token claim ``nonce_supported=false`` does not disable this
check. Applications requiring a provider-specific compatibility exception must
implement that policy explicitly for the trusted provider; do not derive it from
claims in the received token. Passing ``nonce=None`` to ``parse_id_token()`` omits
nonce validation and should only be used when the application has deliberately
chosen a flow without an expected nonce.

The ID Token signature is checked with the algorithms of the provider
``id_token_signing_alg_values_supported`` metadata, or ``RS256`` when this
metadata is missing. Unsigned ID Tokens are always refused. If your provider
uses another algorithm and does not publish this metadata, set it when you
register the client. For ``HS256``, also add the client secret as an ``oct``
key in ``jwks``.

RP-Initiated Logout
-------------------

To implement `OpenID Connect RP-Initiated Logout`_, use the ``logout_redirect`` method
to redirect users to the provider's end session endpoint:

.. code-block:: python

    @app.route('/logout')
    def logout():
        # Retrieve the ID token you stored during login
        id_token = session.pop('id_token', None)
        return oauth.google.logout_redirect(
            post_logout_redirect_uri=url_for('logged_out', _external=True),
            id_token_hint=id_token,
        )

    @app.route('/logged-out')
    def logged_out():
        state_data = oauth.google.validate_logout_response()
        return 'You have been logged out.'

.. _OpenID Connect RP-Initiated Logout: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

The ``logout_redirect`` method accepts:

- ``post_logout_redirect_uri``: Where to redirect after logout (must be registered with the provider)
- ``id_token_hint``: The ID token previously issued (recommended)
- ``state``: Opaque value for CSRF protection (generated when ``post_logout_redirect_uri`` is given and ``state`` is not)
- ``client_id``: OAuth 2.0 Client Identifier (optional)
- ``logout_hint``: Hint about the user logging out (optional)
- ``ui_locales``: Preferred languages for the logout UI (optional)

.. note::

    You must store the ``id_token`` during login to use it later for logout.
    The ``id_token`` is available in ``token['id_token']`` after calling
    ``authorize_access_token()``.

Examples
---------

Here are some example projects for you to learn Flask OAuth 2.0 client integrations:

1. `Flask Google Login`_.

.. _`Flask Google Login`: https://github.com/authlib/demo-oauth-client/tree/master/flask-google-login

.. invisible-code-block: python

    oauth.register(
        "github",
        client_id="Your GitHub client ID",
        client_secret="Your GitHub client secret",
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
    )
    http = app.test_client()
    response = http.get("/login")
    response = http.get(consent(response.location))
    assert response.status_code == 302, response.data
    assert response.location == "/"
