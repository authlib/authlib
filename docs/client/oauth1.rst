.. _oauth_1_session:

OAuth 1 Session
===============

.. meta::
    :description: An OAuth 1.0 protocol Client implementation for Python
        requests and httpx, powered by Authlib.

.. module:: authlib.integrations
    :noindex:

This documentation covers the common design of a Python OAuth 1.0 client.
Authlib provides three implementations of OAuth 1.0 client:

1. :class:`requests_client.OAuth1Session` implementation of :ref:`requests_client`,
   which is a replacement for **requests-oauthlib**.
2. :class:`httpx_client.AsyncOAuth1Client` implementation of :ref:`httpx_client`,
   which is an **async** OAuth 1.0 client.

:class:`requests_client.OAuth1Session` and :class:`httpx_client.AsyncOAuth1Client`
shares the same API.

There are also frameworks integrations of :ref:`flask_client`, :ref:`django_client`
and :ref:`starlette_client`. If you are using these frameworks, you may have interests
in their own documentation.

If you are not familiar with OAuth 1.0, it is better to read :ref:`intro_oauth1` now.

Initialize OAuth 1.0 Client
---------------------------

There are three steps in OAuth 1 to obtain an access token:

1. fetch a temporary credential
2. visit the authorization page
3. exchange access token with the temporary credential

But first, we need to initialize an OAuth 1.0 client::

    >>> client_id = 'Your Twitter client key'
    >>> client_secret = 'Your Twitter client secret'
    >>> # using requests client
    >>> from authlib.integrations.requests_client import OAuth1Session
    >>> client = OAuth1Session(client_id, client_secret)
    >>> # using httpx client
    >>> from authlib.integrations.httpx_client import AsyncOAuth1Client
    >>> client = AsyncOAuth1Client(client_id, client_secret)

.. _fetch_request_token:

Fetch Temporary Credential
--------------------------

The first step is to fetch temporary credential, which will be used to generate
authorization URL::

    >>> request_token_url = 'https://api.twitter.com/oauth/request_token'
    >>> request_token = client.fetch_request_token(request_token_url)
    >>> print(request_token)
    {'oauth_token': 'gA..H', 'oauth_token_secret': 'lp..X', 'oauth_callback_confirmed': 'true'}

Save this temporary credential for later use (if required).

You can assign a ``redirect_uri`` before fetching the request token, if
you want to redirect back to another URL other than the one you registered::

    >>> client.redirect_uri = 'https://your-domain.org/auth'
    >>> client.fetch_request_token(request_token_url)

Redirect to Authorization Endpoint
----------------------------------

The second step is to generate the authorization URL::

    >>> authenticate_url = 'https://api.twitter.com/oauth/authenticate'
    >>> client.create_authorization_url(authenticate_url, request_token['oauth_token'])
    'https://api.twitter.com/oauth/authenticate?oauth_token=gA..H'

Actually, the second parameter ``request_token`` can be omitted, since session
is reused::

    >>> client.create_authorization_url(authenticate_url)

Now visit the authorization url that `create_authorization_url` generated, and
grant the authorization.

.. _fetch_oauth1_access_token:

Fetch Access Token
------------------

When the authorization is granted, you will be redirected back to your
registered callback URI. For instance::

    https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq

If you assigned ``redirect_uri`` in :ref:`fetch_oauth1_access_token`, the
authorize response would be something like::

    https://your-domain.org/auth?oauth_token=gA..H&oauth_verifier=fcg..1Dq

Now fetch the access token with this response::

    >>> resp_url = 'https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq'
    >>> client.parse_authorization_response(resp_url)
    >>> access_token_url = 'https://api.twitter.com/oauth/access_token'
    >>> token = client.fetch_access_token(access_token_url)
    >>> print(token)
    {
        'oauth_token': '12345-st..E',
        'oauth_token_secret': 'o67..X',
        'user_id': '12345',
        'screen_name': 'lepture',
        'x_auth_expires': '0'
    }
    >>> save_access_token(token)

Save this token to access protected resources.

The above flow is not always what we will use in a real project. When we are
redirected to authorization endpoint, our session is over. In this case, when
the authorization server send us back to our server, we need to create another
session::

    >>> # restore your saved request token, which is a dict
    >>> request_token = restore_request_token()
    >>> oauth_token = request_token['oauth_token']
    >>> oauth_token_secret = request_token['oauth_token_secret']
    >>> from authlib.integrations.requests_client import OAuth1Session
    >>> # if using httpx: from authlib.integrations.httpx_client import AsyncOAuth1Client
    >>> client = OAuth1Session(
    ...     client_id, client_secret,
    ...     token=oauth_token,
    ...     token_secret=oauth_token_secret)
    >>> # there is no need for `parse_authorization_response` if you can get `verifier`
    >>> verifier = request.args.get('verifier')
    >>> access_token_url = 'https://api.twitter.com/oauth/access_token'
    >>> token = client.fetch_access_token(access_token_url, verifier)

Access Protected Resources
--------------------------

Now you can access the protected resources. If you reuse the session, you
don't need to do anything::

    >>> account_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    >>> resp = client.get(account_url)
    <Response [200]>
    >>> resp.json()
    {...}

The above is not the real flow, just like what we did in
:ref:`fetch_oauth1_access_token`, we need to create another session ourselves::

    >>> access_token = restore_access_token_from_database()
    >>> oauth_token = access_token['oauth_token']
    >>> oauth_token_secret = access_token['oauth_token_secret']
    >>> # if using httpx: from authlib.integrations.httpx_client import AsyncOAuth1Client
    >>> client = OAuth1Session(
    ...     client_id, client_secret,
    ...     token=oauth_token,
    ...     token_secret=oauth_token_secret)
    >>> account_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    >>> resp = client.get(account_url)

Please note, there are duplicated steps in the documentation, read carefully
and ignore the duplicated explains.

Using OAuth1Auth
----------------

It is also possible to access protected resources with ``OAuth1Auth`` object.
Create an instance of OAuth1Auth with an access token::

    # if using requests
    from authlib.integrations.requests_client import OAuth1Auth

    # if using httpx
    from authlib.integrations.httpx_client import OAuth1Auth

    auth = OAuth1Auth(
        client_id='..',
        client_secret='..',
        token='oauth_token value',
        token_secret='oauth_token_secret value',
        ...
    )

If using ``requests``, pass this ``auth`` to access protected resources::

    import requests

    url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    resp = requests.get(url, auth=auth)

If using ``httpx``, pass this ``auth`` to access protected resources::

    import httpx

    url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    resp = await httpx.get(url, auth=auth)

