.. _oauth_1_session:

HTTP Clients
============

.. meta::
    :description: An OAuth 1.0 protocol Client implementation for Python
        requests and httpx2, powered by Authlib.

.. module:: authlib.integrations
    :noindex:

This documentation covers the common design of a Python OAuth 1.0 client.
Authlib provides OAuth 1.0 clients for two HTTP libraries:

1. :class:`requests_client.OAuth1Session` implementation of :ref:`requests_client`,
   which is a replacement for **requests-oauthlib**.
2. :class:`httpx_client.OAuth1Client` and :class:`httpx_client.AsyncOAuth1Client`
   implementations of :ref:`httpx_client`, which are sync and **async** OAuth 1.0
   clients.

:class:`requests_client.OAuth1Session` and :class:`httpx_client.AsyncOAuth1Client`
shares the same API.

If you are not familiar with OAuth 1.0, it is better to read :ref:`intro_oauth1` now.

.. toctree::
    :maxdepth: 1

    requests
    httpx
    api

Initialize OAuth 1.0 Client
---------------------------

There are three steps in OAuth 1 to obtain an access token:

1. fetch a temporary credential
2. visit the authorization page
3. exchange access token with the temporary credential

But first, we need to initialize an OAuth 1.0 client:

.. code-block:: pycon

    >>> from authlib.integrations.requests_client import OAuth1Session
    >>> client_id = 'Your Twitter client key'
    >>> client_secret = 'Your Twitter client secret'
    >>> redirect_uri = 'https://example.com/twitter'
    >>> client = OAuth1Session(client_id, client_secret, redirect_uri=redirect_uri)

Per RFC 5849 §2.1, the request of a temporary credential requires a
``redirect_uri``, the ``oauth_callback`` parameter. Use ``'oob'`` if the client
cannot receive the redirection.

With HTTPX2, :class:`httpx_client.AsyncOAuth1Client` takes the same arguments.
Add ``await`` before the methods that send a request, see :ref:`httpx_oauth1_client`.

.. _fetch_request_token:

Fetch Temporary Credential
--------------------------

The first step is to fetch temporary credential, which will be used to generate
authorization URL:

.. code-block:: pycon

    >>> request_token_url = 'https://api.twitter.com/oauth/request_token'
    >>> request_token = client.fetch_request_token(request_token_url)
    >>> print(request_token)
    {'oauth_token': '...', 'oauth_token_secret': '...', 'oauth_callback_confirmed': 'true'}

Save this temporary credential for later use (if required).

You can assign a ``redirect_uri`` before fetching the request token, if
you want to redirect back to another URL other than the one you registered:

.. invisible-code-block: python

    client = OAuth1Session(client_id, client_secret)

.. code-block:: pycon

    >>> client.redirect_uri = 'https://your-domain.org/auth'
    >>> request_token = client.fetch_request_token(request_token_url)

Redirect to Authorization Endpoint
----------------------------------

The second step is to generate the authorization URL:

.. code-block:: pycon

    >>> authenticate_url = 'https://api.twitter.com/oauth/authenticate'
    >>> client.create_authorization_url(authenticate_url, request_token['oauth_token'])
    'https://api.twitter.com/oauth/authenticate?oauth_token=...'

Actually, the second parameter ``request_token`` can be omitted, since session
is reused:

.. code-block:: pycon

    >>> client.create_authorization_url(authenticate_url)
    'https://api.twitter.com/oauth/authenticate?oauth_token=...'

Now visit the authorization url that `create_authorization_url` generated, and
grant the authorization.

.. _fetch_oauth1_access_token:

Fetch Access Token
------------------

When the authorization is granted, you will be redirected back to your
registered callback URI. For instance:

.. code-block:: text

    https://example.com/twitter?oauth_token=gA..H&oauth_verifier=fcg..1Dq

If you assigned ``redirect_uri`` in :ref:`fetch_request_token`, the
authorize response would be something like:

.. code-block:: text

    https://your-domain.org/auth?oauth_token=gA..H&oauth_verifier=fcg..1Dq

Now fetch the access token with the URL of this response, ``resp_url``, for
instance ``request.url`` with Flask:

.. invisible-code-block: python

    resp_url = consent(client.create_authorization_url(authenticate_url))

    def save_access_token(token):
        pass

.. code-block:: pycon

    >>> client.parse_authorization_response(resp_url)
    {'oauth_token': '...', 'oauth_verifier': '...'}
    >>> access_token_url = 'https://api.twitter.com/oauth/access_token'
    >>> token = client.fetch_access_token(access_token_url)
    >>> print(token)
    {'oauth_token': '...', 'oauth_token_secret': '...'}
    >>> save_access_token(token)

Save this token to access protected resources.

The above flow is not always what we will use in a real project. When we are
redirected to authorization endpoint, our session is over. In this case, when
the authorization server send us back to our server, we need to create another
session:

.. invisible-code-block: python

    from types import SimpleNamespace
    from urllib.parse import parse_qsl, urlsplit

    saved_request_token = OAuth1Session(
        client_id, client_secret, redirect_uri=redirect_uri
    ).fetch_request_token(request_token_url)
    callback = consent(f"{authenticate_url}?oauth_token={saved_request_token['oauth_token']}")
    request = SimpleNamespace(args=dict(parse_qsl(urlsplit(callback).query)))

    def restore_request_token():
        return saved_request_token

.. code-block:: pycon

    >>> # restore your saved request token, which is a dict
    >>> request_token = restore_request_token()
    >>> oauth_token = request_token['oauth_token']
    >>> oauth_token_secret = request_token['oauth_token_secret']
    >>> client = OAuth1Session(
    ...     client_id, client_secret,
    ...     token=oauth_token,
    ...     token_secret=oauth_token_secret)
    >>> # there is no need for `parse_authorization_response` if you can get `oauth_verifier`
    >>> verifier = request.args.get('oauth_verifier')
    >>> access_token_url = 'https://api.twitter.com/oauth/access_token'
    >>> token = client.fetch_access_token(access_token_url, verifier)

Access Protected Resources
--------------------------

Now you can access the protected resources. If you reuse the session, you
don't need to do anything:

.. code-block:: pycon

    >>> account_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    >>> resp = client.get(account_url)
    >>> resp
    <Response [200]>
    >>> resp.json()
    {...}

The above is not the real flow, just like what we did in
:ref:`fetch_oauth1_access_token`, we need to create another session ourselves:

.. invisible-code-block: python

    saved_access_token = token

    def restore_access_token_from_database():
        return saved_access_token

.. code-block:: pycon

    >>> access_token = restore_access_token_from_database()
    >>> oauth_token = access_token['oauth_token']
    >>> oauth_token_secret = access_token['oauth_token_secret']
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
Create an instance of OAuth1Auth with an access token. If using ``requests``,
pass this ``auth`` to access protected resources:

.. code-block:: python

    import requests
    from authlib.integrations.requests_client import OAuth1Auth

    auth = OAuth1Auth(
        client_id=client_id,
        client_secret=client_secret,
        token=oauth_token,
        token_secret=oauth_token_secret,
    )
    url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    resp = requests.get(url, auth=auth)

If using ``httpx2``, use the ``OAuth1Auth`` of the HTTPX2 integration:

.. code-block:: python

    import httpx2
    from authlib.integrations.httpx_client import OAuth1Auth

    auth = OAuth1Auth(
        client_id=client_id,
        client_secret=client_secret,
        token=oauth_token,
        token_secret=oauth_token_secret,
    )
    url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    resp = httpx2.get(url, auth=auth)

.. invisible-code-block: python

    assert resp.status_code == 200, resp.text

