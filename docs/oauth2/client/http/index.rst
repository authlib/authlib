.. _oauth_2_session:

HTTP Clients
============

.. meta::
    :description: An OAuth 2.0 Client implementation for Python requests,
        and httpx2, powered by Authlib.

.. module:: authlib.integrations
    :noindex:


This documentation covers the common design of a Python OAuth 2.0 client.
Authlib provides OAuth 2.0 clients for two HTTP libraries:

1. :class:`requests_client.OAuth2Session` implementation of :ref:`requests_client`,
   which is a replacement for **requests-oauthlib**.
2. :class:`httpx_client.OAuth2Client` and :class:`httpx_client.AsyncOAuth2Client`
   implementations of :ref:`httpx_client`, which are sync and **async** OAuth 2.0
   clients powered by **HTTPX2**.

:class:`requests_client.OAuth2Session` and :class:`httpx_client.AsyncOAuth2Client`
shares the same API.

If you are not familiar with OAuth 2.0, it is better to read :ref:`intro_oauth2` now.

.. toctree::
    :maxdepth: 1

    requests
    httpx
    api


OAuth2Session for Authorization Code
------------------------------------

There are two steps in OAuth 2 to obtain an access token with authorization
code grant type. Initialize the session for reuse:

.. code-block:: pycon

    >>> from authlib.integrations.requests_client import OAuth2Session
    >>> client_id = 'Your GitHub client ID'
    >>> client_secret = 'Your GitHub client secret'
    >>> scope = 'user:email'  # we want to fetch user's email
    >>> client = OAuth2Session(client_id, client_secret, scope=scope)

With HTTPX2, :class:`httpx_client.AsyncOAuth2Client` takes the same arguments.
Add ``await`` before the methods that send a request, see :ref:`httpx_client`.

You can assign a ``redirect_uri`` in case you want to specify the callback
url.

Redirect to Authorization Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike OAuth 1, there is no request token. The first step is to jump to
the remote authorization server:

.. code-block:: pycon

    >>> authorization_endpoint = 'https://github.com/login/oauth/authorize'
    >>> uri, state = client.create_authorization_url(authorization_endpoint)
    >>> print(uri)
    https://github.com/login/oauth/authorize?response_type=code&client_id=...&scope=user%3Aemail&state=...

The ``create_authorization_url`` returns a tuple of ``(uri, state)``. Save the
state, for instance in the user session. The client does not keep it.

Now head over to the generated authorization url, and grant the authorization.

.. _fetch_oauth2_access_token:

Fetch Token
~~~~~~~~~~~

The authorization server will redirect you back to your site with a code and
state arguments:

.. code-block:: text

    https://example.com/github?code=42..e9&state=d..t

Use the URL of this request as ``authorization_response``, for instance
``request.url`` with Flask. Use ``.fetch_token`` to obtain access token. Pass
the saved ``state``. The client then raises ``MismatchingStateException`` when
the ``state`` of the response is different. This check protects against CSRF
attacks. Without ``state``, the client does not check it:

.. invisible-code-block: python

    authorization_response = consent(uri)

.. code-block:: pycon

    >>> token_endpoint = 'https://github.com/login/oauth/access_token'
    >>> token = client.fetch_token(
    ...     token_endpoint, authorization_response=authorization_response, state=state
    ... )
    >>> print(token)
    {'access_token': '...', ..., 'scope': 'user:email', 'token_type': 'Bearer', ...}

Save this token to access users' protected resources.

In real project, this session can not be reused since you are redirected to
another website. You need to create another session yourself. The ``state``
passed to the constructor is checked by ``fetch_token``:

.. invisible-code-block: python

    uri, state = client.create_authorization_url(authorization_endpoint)
    authorization_response = consent(uri)

    def restore_previous_state():
        return state

.. code-block:: pycon

    >>> state = restore_previous_state()
    >>> client = OAuth2Session(client_id, client_secret, state=state)
    >>> token = client.fetch_token(token_endpoint, authorization_response=authorization_response)

Authlib has a built-in Flask/Django integration. Learn from them.

Add PKCE for Authorization Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authlib client can handle PKCE automatically, just pass ``code_verifier`` to ``create_authorization_url``
and ``fetch_token``:

.. code-block:: pycon

    >>> from authlib.common.security import generate_token
    >>> client = OAuth2Session(client_id, client_secret, code_challenge_method='S256')
    >>> code_verifier = generate_token(48)
    >>> uri, state = client.create_authorization_url(authorization_endpoint, code_verifier=code_verifier)

After the redirection, fetch the token with the same ``code_verifier``:

.. invisible-code-block: python

    authorization_response = consent(uri)

.. code-block:: pycon

    >>> token = client.fetch_token(
    ...     token_endpoint,
    ...     authorization_response=authorization_response,
    ...     code_verifier=code_verifier,
    ... )

The supported methods are ``S256`` and ``plain``. Prefer ``S256``, per
:rfc:`RFC 9700 §2.1.1 <9700#section-2.1.1>`.


OAuth2Session for Implicit
--------------------------

OAuth2Session supports implicit grant type. It can fetch the access token with
the ``response_type`` of ``token``:

.. code-block:: pycon

    >>> authorization_endpoint = 'https://some-service.com/oauth/authorize'
    >>> uri, state = client.create_authorization_url(authorization_endpoint, response_type='token')
    >>> print(uri)
    https://some-service.com/oauth/authorize?response_type=token&client_id=...

Visit this link, and grant the authorization, the OAuth authorization server will
redirect back to your redirect_uri, the response url would be something like:

.. code-block:: text

    https://example.com/cb#access_token=2..WpA&state=xyz&token_type=bearer&expires_in=3600

Fetch access token from the fragment with ``.fetch_token`` method:

.. invisible-code-block: python

    authorization_response = consent(uri)

.. code-block:: pycon

    >>> token = client.fetch_token(authorization_response=authorization_response)
    >>> # if you don't specify access token endpoint, it will fetch from fragment.
    >>> print(token)
    {'token_type': 'Bearer', 'access_token': '...', ...}

.. note:: GitHub doesn't support ``token`` response type, try with other services.


OAuth2Session for Password
--------------------------

The ``password`` grant type is supported since Version 0.5. Use ``username``
and ``password`` to fetch the access token:

.. code-block:: pycon

    >>> token = client.fetch_token(token_endpoint, username='a-name', password='a-password')

OAuth2Session for Client Credentials
------------------------------------

The ``client_credentials`` grant type is supported since Version 0.5. If no
``code`` or no user info provided, it would be a ``client_credentials``
request. But it is suggested that you specify a ``grant_type`` for it:

.. invisible-code-block: python

    client = OAuth2Session(client_id, client_secret)

.. code-block:: pycon

    >>> token = client.fetch_token(token_endpoint)
    >>> # or with grant_type
    >>> token = client.fetch_token(token_endpoint, grant_type='client_credentials')

.. _oauth2_client_auth:

Client Authentication
---------------------

When fetching access token, the authorization server will require a client
authentication, Authlib provides **three default methods** defined by RFC 7591:

- client_secret_basic
- client_secret_post
- none

The default value is ``client_secret_basic``. You can change the auth method
with ``token_endpoint_auth_method``:

.. code-block:: pycon

    >>> client = OAuth2Session(token_endpoint_auth_method='client_secret_post')

If the authorization server requires other means of authentication, you can
construct an ``auth`` for your own need, and pass it to ``fetch_token``:

.. skip: start "uses your own auth class"

.. code-block:: pycon

    >>> auth = YourAuth(...)
    >>> token = client.fetch_token(token_endpoint, auth=auth, ...)

.. skip: end

It is also possible to extend the client authentication method with
``.register_client_auth_method``. Besides the default three authentication
methods, there are more provided by Authlib. e.g.

- client_secret_jwt
- private_key_jwt

These two methods are defined by RFC 7523 and OpenID Connect. Find more in
:ref:`jwt_oauth2session`.

There are still cases that developers need to define a custom client
authentication method. Take :issue:`158` as an example, the provider
requires us put ``client_id`` and ``client_secret`` on URL when sending
POST request:

.. code-block:: http

    POST /oauth/token?grant_type=code&code=...&client_id=...&client_secret=... HTTP/1.1

Let's call this weird authentication method ``client_secret_uri``, and this
is how we can get our OAuth 2.0 client authenticated:

.. code-block:: python

    from authlib.common.urls import add_params_to_uri

    def auth_client_secret_uri(client, method, uri, headers, body):
        uri = add_params_to_uri(uri, [
            ('client_id', client.client_id),
            ('client_secret', client.client_secret),
        ])
        uri = uri + '&' + body
        body = ''
        return uri, headers, body

    client = OAuth2Session(
        'client_id', 'client_secret',
        token_endpoint_auth_method='client_secret_uri',
    )
    client.register_client_auth_method(('client_secret_uri', auth_client_secret_uri))

With ``client_secret_uri`` registered, OAuth 2.0 client will authenticate with
the signed URI. It is also possible to assign the function to ``token_endpoint_auth_method``
directly:

.. code-block:: python

    client = OAuth2Session(
        'client_id', 'client_secret',
        token_endpoint_auth_method=auth_client_secret_uri,
    )

Access Protected Resources
--------------------------

Now you can access the protected resources. If you reuse the session, you
don't need to do anything:

.. invisible-code-block: python

    saved_token = OAuth2Session(client_id, client_secret).fetch_token(
        token_endpoint, username="alice", password="secret"
    )
    client = OAuth2Session(client_id, client_secret, token=saved_token)

    def restore_previous_token_from_database():
        return saved_token

    get_your_previous_saved_token = restore_previous_token_from_database

.. code-block:: pycon

    >>> account_url = 'https://api.github.com/user'
    >>> resp = client.get(account_url)
    >>> resp
    <Response [200]>
    >>> resp.json()
    {...}

The above is not the real flow, just like what we did in
:ref:`fetch_oauth2_access_token`, we need to create another session
ourselves:

.. code-block:: pycon

    >>> token = restore_previous_token_from_database()
    >>> # token is a dict which must contain ``access_token``, ``token_type``
    >>> client = OAuth2Session(client_id, client_secret, token=token)
    >>> account_url = 'https://api.github.com/user'
    >>> resp = client.get(account_url)


Refresh & Auto Update Token
---------------------------

It is possible that your previously saved token is expired when accessing
protected resources. In this case, we can refresh the token manually, or even
better, Authlib will refresh the token automatically and update the token
for us.

Automatically refreshing tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If your :class:`~requests_client.OAuth2Session` class was created with the
`token_endpoint` parameter, Authlib will automatically refresh the token when
it has expired:

.. code-block:: pycon

    >>> openid_configuration = requests.get("https://example.org/.well-known/openid-configuration").json()
    >>> session = OAuth2Session(
    ...     client_id, client_secret, token_endpoint=openid_configuration["token_endpoint"]
    ... )

By default, the token will be refreshed 60 seconds before its actual expiry time, to avoid clock skew issues.
You can control this behaviour by setting the ``leeway`` parameter of the :class:`~requests_client.OAuth2Session`
class.

Automatically fetching new tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``client_credentials`` grant has no refresh token. When the token has
expired, Authlib fetches a new one if the client knows the grant. This is the
case after ``fetch_token`` was called with this grant. If you create the client
with a saved token instead, pass ``grant_type``:

.. code-block:: pycon

    >>> session = OAuth2Session(
    ...     client_id, client_secret, token=token,
    ...     token_endpoint=token_endpoint, grant_type="client_credentials",
    ... )

The extra parameters of the first ``fetch_token`` call, such as ``audience``,
are not sent again. Pass them with ``access_token_params`` instead:

.. code-block:: pycon

    >>> session = OAuth2Session(
    ...     client_id, client_secret, token=token,
    ...     token_endpoint=token_endpoint, grant_type="client_credentials",
    ...     access_token_params={"audience": "https://api.example.com"},
    ... )

With the framework integrations, put ``grant_type`` in ``client_kwargs``. The
``access_token_params`` given to ``register()`` are sent with these requests too.

Manually refreshing tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~

To call :meth:`~requests_client.OAuth2Session.refresh_token` manually means
we are going to exchange a new "access_token" with "refresh_token":

.. code-block:: pycon

    >>> token = restore_previous_token_from_database()
    >>> new_token = client.refresh_token(token_endpoint, refresh_token=token['refresh_token'])

When the client refreshes the token automatically, it calls the ``update_token``
function given to the constructor. Use it to save the new token:

.. code-block:: python

    def update_token(token, refresh_token=None, access_token=None):
        if refresh_token:
            item = OAuth2Token.find(refresh_token=refresh_token)
        elif access_token:
            item = OAuth2Token.find(access_token=access_token)
        else:
            return

        item.access_token = token['access_token']
        item.refresh_token = token.get('refresh_token')
        item.expires_at = token['expires_at']
        item.save()

    client = OAuth2Session(
        client_id, client_secret,
        token_endpoint=token_endpoint,
        update_token=update_token,
    )

When sending a request to resources endpoint, if our previously saved token
is expired, this ``client`` will invoke ``.refresh_token`` method itself and
call this our defined ``update_token`` to save the new token:

.. code-block:: python

    token = restore_previous_token_from_database()
    client.token = token

    # if the token is expired, this GET request will update token
    client.get('https://openidconnect.googleapis.com/v1/userinfo')

Revoke and Introspect Token
---------------------------

If the provider support token revocation and introspection, you can revoke
and introspect the token with:

.. code-block:: python

    revocation_endpoint = 'https://example.com/oauth/revoke'
    introspection_endpoint = 'https://example.com/oauth/introspect'

    token = get_your_previous_saved_token()
    client.introspect_token(introspection_endpoint, token=token['access_token'])
    client.revoke_token(revocation_endpoint, token=token['refresh_token'])

Without ``token``, the client uses the refresh token of ``client.token``, or
its access token when it has no refresh token.

You can find the available parameters in API docs:

- :meth:`requests_client.OAuth2Session.revoke_token`
- :meth:`requests_client.OAuth2Session.introspect_token`
- :meth:`httpx_client.AsyncOAuth2Client.revoke_token`
- :meth:`httpx_client.AsyncOAuth2Client.introspect_token`

.. _compliance_fix_oauth2:

Compliance Fix for non Standard
-------------------------------

There are services that claimed they are providing OAuth API, but with a little
differences. Some services even return with the wrong Content Type. Compliance
hooks are provided to solve those problems:

* ``access_token_response``: invoked before token parsing.
* ``refresh_token_request``: invoked before refreshing token.
* ``refresh_token_response``: invoked before refresh token parsing.
* ``protected_request``: invoked before making a request.
* ``revoke_token_request``: invoked before revoking a token.
* ``introspect_token_request``: invoked before introspecting a token.

For instance, Stackoverflow requires a ``site`` parameter in the query
string to protect users' resources. And stackoverflow's response is
not in JSON. Let's fix it:

.. invisible-code-block: python

    session = OAuth2Session(client_id, client_secret)

.. code-block:: python

    from authlib.common.urls import add_params_to_uri, url_decode

    def _non_compliant_param_name(url, headers, body):
        params = {'site': 'stackoverflow'}
        url = add_params_to_uri(url, params)
        return url, headers, body

    def _fix_token_response(resp):
        data = dict(url_decode(resp.text))
        data['token_type'] = 'Bearer'
        data['expires_in'] = int(data['expires'])
        resp.json = lambda: data
        return resp

    session.register_compliance_hook(
        'protected_request', _non_compliant_param_name)
    session.register_compliance_hook(
        'access_token_response', _fix_token_response)

If you find a non standard OAuth 2 services, and you can't fix it. Please
report it in GitHub issues.

.. _oidc_session:

OAuth 2 OpenID Connect
----------------------

For services that support OpenID Connect, if a scope of ``openid`` is provided,
the authorization server will return a value of ``id_token`` in response:

.. code-block:: pycon

    >>> client_id = 'Your Google client ID'
    >>> client_secret = 'Your Google client secret'
    >>> scope = 'openid email profile'
    >>> redirect_uri = 'https://example.com/cb'
    >>> client = OAuth2Session(client_id, client_secret, scope=scope, redirect_uri=redirect_uri)

The remote server may require other parameters for OpenID Connect requests, for
instance, it may require a ``nonce`` parameter, in this case, you need to
generate it yourself, and pass it to ``create_authorization_url``:

.. code-block:: pycon

    >>> from authlib.common.security import generate_token
    >>> # remember to save this nonce for verification
    >>> nonce = generate_token()
    >>> authorization_endpoint = 'https://accounts.google.com/o/oauth2/v2/auth'
    >>> uri, state = client.create_authorization_url(authorization_endpoint, nonce=nonce)

At the last step of ``client.fetch_token``, the return value contains
a ``id_token``:

.. invisible-code-block: python

    authorization_response = consent(uri)

.. code-block:: pycon

    >>> token_endpoint = 'https://oauth2.googleapis.com/token'
    >>> resp = client.fetch_token(token_endpoint, authorization_response=authorization_response)
    >>> print(resp['id_token'])
    eyJ...

This ``id_token`` is a JWT text, it can not be used unless it is parsed.
Authlib has provided tools for parsing and validating OpenID Connect id_token.
Pass the issuer, the client ID and the saved nonce, so that ``validate`` checks
the ``iss``, ``aud`` and ``nonce`` claims (OpenID Connect Core 1.0 §3.1.3.7):

.. code-block:: pycon

    >>> from authlib.oidc.core import CodeIDToken
    >>> from joserfc import jwt
    >>> from joserfc.jwk import KeySet
    >>> certs = requests.get('https://www.googleapis.com/oauth2/v3/certs').json()
    >>> keys = KeySet.import_key_set(certs)
    >>> token = jwt.decode(resp['id_token'], keys)
    >>> claims = CodeIDToken(
    ...     token.claims,
    ...     token.header,
    ...     options={'iss': {'value': 'https://accounts.google.com'}},
    ...     params={
    ...         'client_id': client_id,
    ...         'nonce': nonce,
    ...         'access_token': resp['access_token'],
    ...     },
    ... )
    >>> claims.validate()

.. versionchanged:: 1.7
    We use joserfc_ for JWT encoding and decoding. Checkout the JWT guide
    on https://jose.authlib.org/en/guide/jwt/

.. _joserfc: https://jose.authlib.org/en/

.. _assertion_session:

AssertionSession
----------------

:class:`~requests_client.AssertionSession` is a Requests Session for Assertion
Framework of OAuth 2.0 Authorization Grants. It is also know as service account.
A configured ``AssertionSession`` with handle token authorization automatically,
which means you can just use it.

Take `Google Service Account`_ as an example, with the information in your
service account JSON configure file:

.. skip: next "reads a service account file"

.. code-block:: python

    import json
    from authlib.integrations.requests_client import AssertionSession

    with open('MyProject-1234.json') as f:
        conf = json.load(f)

    token_uri = conf['token_uri']
    header = {'alg': 'RS256'}
    key_id = conf.get('private_key_id')
    if key_id:
        header['kid'] = key_id

    # Google puts scope in payload
    claims = {'scope': scope}

    session = AssertionSession(
        token_endpoint=token_uri,
        issuer=conf['client_email'],
        audience=token_uri,
        claims=claims,
        subject=None,
        key=conf['private_key'],
        header=header,
    )
    session.get(...)
    session.post(...)

There is a ready to use ``GoogleServiceAccount`` in loginpass_. You can
also read these posts:

- `Access Google Analytics API <https://blog.authlib.org/2018/access-google-analytics-api>`_.
- `Using Authlib with gspread <https://blog.authlib.org/2018/authlib-for-gspread>`_.

.. _loginpass: https://github.com/authlib/loginpass
.. _`Google Service Account`: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
