.. _starlette_client:

Starlette Integration
=====================

.. meta::
    :description: The built-in Starlette integrations for OAuth 2.0
        and OpenID Connect clients, powered by Authlib.

.. module:: authlib.integrations.starlette_client
    :noindex:

Starlette_ is a lightweight ASGI framework/toolkit, which is ideal for
building high performance asyncio services.

.. _Starlette: https://www.starlette.io/

This documentation covers OAuth 2.0 and OpenID Connect Client support for
Starlette. Because all the frameworks integrations share the same API, it is
best to:

Read :ref:`frameworks_clients` at first.

The difference between Starlette and Flask/Django integrations is Starlette
is **async**. We will use ``await`` for the functions we need to call. But
first, let's create an :class:`OAuth` instance:

.. code-block:: python

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

Register Remote Apps
--------------------

``oauth.register`` is the same as :ref:`frameworks_clients`:

.. code-block:: python

    oauth.register(
        'google',
        client_id='Your Google client ID',
        client_secret='Your Google client secret',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    )

However, unlike Flask/Django, Starlette OAuth registry uses HTTPX2
:class:`~authlib.integrations.httpx_client.AsyncOAuth2Client` as the OAuth 2.0
backend. While Flask and Django are using the Requests version of
:class:`~authlib.integrations.requests_client.OAuth2Session`.

Routes for Authorization
------------------------

Just like the examples in :ref:`frameworks_clients`, but Starlette is **async**,
the routes for authorization should look like:

.. code-block:: python

    from starlette.responses import RedirectResponse

    async def login_via_google(request):
        google = oauth.create_client('google')
        redirect_uri = request.url_for('authorize_google')
        return await google.authorize_redirect(request, redirect_uri)

    async def authorize_google(request):
        google = oauth.create_client('google')
        token = await google.authorize_access_token(request)
        # do something with the token and userinfo
        return RedirectResponse('/')

    app.add_route('/login/google', login_via_google)
    app.add_route('/auth/google', authorize_google)

Starlette OpenID Connect
------------------------

An OpenID Connect client is no different than a normal OAuth 2.0 client, just add
``openid`` scope when ``.register``. The built-in Starlette OAuth client will handle
everything automatically:

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

    token = await oauth.google.authorize_access_token(request)

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

    async def logout(request):
        # Retrieve the ID token you stored during login
        id_token = request.session.pop('id_token', None)
        redirect_uri = request.url_for('logged_out')
        return await oauth.google.logout_redirect(
            request,
            post_logout_redirect_uri=str(redirect_uri),
            id_token_hint=id_token,
        )

    async def logged_out(request):
        state_data = await oauth.google.validate_logout_response(request)
        return PlainTextResponse('You have been logged out.')

    app.add_route('/logout', logout)
    app.add_route('/logged-out', logged_out)

.. _OpenID Connect RP-Initiated Logout: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

The ``logout_redirect`` method accepts:

- ``request``: The Starlette request object (required)
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
--------

We have Starlette demos at https://github.com/authlib/demo-oauth-client

1. `Starlette Google login <https://github.com/authlib/demo-oauth-client/tree/master/starlette-google-login>`_

.. invisible-code-block: python

    from starlette.testclient import TestClient

    http = TestClient(app)
    response = http.get("/login/google", follow_redirects=False)
    callback = consent(response.headers["location"])
    response = http.get(callback, follow_redirects=False)
    assert response.status_code == 307, response.text
    assert response.headers["location"] == "/"
