.. _frameworks_clients:

Web OAuth Clients
=================

.. module:: authlib.integrations
    :noindex:

This documentation covers OAuth 1.0 and OAuth 2.0 integrations for
Python Web Frameworks like:

* Django: The web framework for perfectionists with deadlines
* Flask: The Python micro framework for building web applications
* Starlette: The little ASGI framework that shines


Authlib shares a common API design among these web frameworks. Instead
of introducing them one by one, this documentation contains the common
usage for them all.

We start with creating a registry with the ``OAuth`` class::

    # for Flask framework
    from authlib.integrations.flask_client import OAuth

    # for Django framework
    from authlib.integrations.django_client import OAuth

    # for Starlette framework
    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()

There are little differences among each framework, you can read their
documentation later:

1. :class:`flask_client.OAuth` for :ref:`flask_client`
2. :class:`django_client.OAuth` for :ref:`django_client`
3. :class:`starlette_client.OAuth` for :ref:`starlette_client`

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter, GitHub, Google etc.

Log In with OAuth 1.0
---------------------

For instance, Twitter is an OAuth 1.0 service, you want your users to log in
your website with Twitter.

The first step is register a remote application on the ``OAuth`` registry via
``oauth.register`` method::

    oauth.register(
        name='twitter',
        client_id='{{ your-twitter-consumer-key }}',
        client_secret='{{ your-twitter-consumer-secret }}',
        request_token_url='https://api.twitter.com/oauth/request_token',
        request_token_params=None,
        access_token_url='https://api.twitter.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://api.twitter.com/oauth/authenticate',
        authorize_params=None,
        api_base_url='https://api.twitter.com/1.1/',
        client_kwargs=None,
    )

The first parameter in ``register`` method is the **name** of the remote
application. You can access the remote application with::

    twitter = oauth.create_client('twitter')
    # or simply with
    twitter = oauth.twitter

The configuration of those parameters can be loaded from the framework
configuration. Each framework has its own config system, read the framework
specified documentation later.

For instance, if ``client_id`` and ``client_secret`` can be loaded via
configuration, we can simply register the remote app with::

    oauth.register(
        name='twitter',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
        api_base_url='https://api.twitter.com/1.1/',
    )

The ``client_kwargs`` is a dict configuration to pass extra parameters to
:ref:`oauth_1_session`. If you are using ``RSA-SHA1`` signature method::

    client_kwargs = {
        'signature_method': 'RSA-SHA1',
        'signature_type': 'HEADER',
        'rsa_key': 'Your-RSA-Key'
    }


Saving Temporary Credential
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Usually, the framework integration has already implemented this part through
the framework session system. All you need to do is enable session for the
chosen framework.

Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After configuring the ``OAuth`` registry and the remote application, the
rest steps are much simpler. The only required parts are routes:

1. redirect to 3rd party provider (Twitter) for authentication
2. redirect back to your website to fetch access token and profile

Here is the example for Twitter login::

    def login(request):
        twitter = oauth.create_client('twitter')
        redirect_uri = 'https://example.com/authorize'
        return twitter.authorize_redirect(request, redirect_uri)

    def authorize(request):
        twitter = oauth.create_client('twitter')
        token = twitter.authorize_access_token(request)
        resp = twitter.get('account/verify_credentials.json')
        resp.raise_for_status()
        profile = resp.json()
        # do something with the token and profile
        return '...'

After user confirmed on Twitter authorization page, it will redirect
back to your website ``authorize`` page. In this route, you can get your
user's twitter profile information, you can store the user information
in your database, mark your user as logged in and etc.


Using OAuth 2.0 to Log In
-------------------------

For instance, GitHub is an OAuth 2.0 service, you want your users to log in
your website with GitHub.

The first step is register a remote application on the ``OAuth`` registry via
``oauth.register`` method::

    oauth.register(
        name='github',
        client_id='{{ your-github-client-id }}',
        client_secret='{{ your-github-client-secret }}',
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )

The first parameter in ``register`` method is the **name** of the remote
application. You can access the remote application with::

    github = oauth.create_client('github')
    # or simply with
    github = oauth.github

The configuration of those parameters can be loaded from the framework
configuration. Each framework has its own config system, read the framework
specified documentation later.

The ``client_kwargs`` is a dict configuration to pass extra parameters to
:ref:`oauth_2_session`, you can pass extra parameters like::

    client_kwargs = {
        'scope': 'profile',
        'token_endpoint_auth_method': 'client_secret_basic',
        'token_placement': 'header',
    }

There are several ``token_endpoint_auth_method``, get a deep inside the
:ref:`client_auth_methods`.

.. note::

    Authlib is using ``request_token_url`` to detect if the client is an
    OAuth 1.0 or OAuth 2.0 client. In OAuth 2.0, there is no ``request_token_url``.


Routes for Authorization
~~~~~~~~~~~~~~~~~~~~~~~~

After configuring the ``OAuth`` registry and the remote application, the
rest steps are much simpler. The only required parts are routes:

1. redirect to 3rd party provider (GitHub) for authentication
2. redirect back to your website to fetch access token and profile

Here is the example for GitHub login::

    def login(request):
        github = oauth.create_client('github')
        redirect_uri = 'https://example.com/authorize'
        return github.authorize_redirect(request, redirect_uri)

    def authorize(request):
        token = oauth.github.authorize_access_token(request)
        resp = oauth.github.get('user', token=token)
        resp.raise_for_status()
        profile = resp.json()
        # do something with the token and profile
        return '...'

After user confirmed on GitHub authorization page, it will redirect
back to your website ``authorize``. In this route, you can get your
user's GitHub profile information, you can store the user information
in your database, mark your user as logged in and etc.

.. note::

    You may find that our documentation for OAuth 1.0 and OAuth 2.0 are
    the same. They are designed to share the same API, so that you use
    the same code for both OAuth 1.0 and OAuth 2.0.

    The ONLY difference is the configuration. OAuth 1.0 contains
    ``request_token_url`` and ``request_token_params`` while OAuth 2.0
    not. Also, the ``client_kwargs`` are different.


Client Authentication Methods
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When fetching access token, the authorization server will require a client
authentication, Authlib provides **three default methods** defined by RFC7591:

- ``client_secret_basic``
- ``client_secret_post``
- ``none``

But if the remote provider does not support these three methods, we need to
register our own authentication methods, like :ref:`oauth2_client_auth`::

    from authlib.oauth2.rfc7523 import ClientSecretJWT

    oauth.register(
        'name',
        ...
        client_auth_methods=[
            ClientSecretJWT(token_endpoint),  # client_secret_jwt
        ]
    )

.. versionadded:: v0.15

    Starting from v0.15, developers can add custom authentication methods
    directly to token endpoint::

        oauth.register(
            'name',
            ...
            token_endpoint_auth_method=ClientSecretJWT(token_endpoint),
        )

Accessing OAuth Resources
-------------------------

.. note::

    If your application ONLY needs login via 3rd party services like
    Twitter, Google, Facebook and GitHub to login, you DON'T need to
    create the token database.

There are also chances that you need to access your user's 3rd party
OAuth provider resources. For instance, you want to display the logged
in user's twitter time line and GitHub repositories. You will use
**access token** to fetch the resources::

    def get_twitter_tweets(request):
        token = OAuth1Token.find(
            name='twitter',
            user=request.user
        )
        # API URL: https://api.twitter.com/1.1/statuses/user_timeline.json
        resp = oauth.twitter.get('statuses/user_timeline.json', token=token.to_token())
        resp.raise_for_status()
        return resp.json()

    def get_github_repositories(request):
        token = OAuth2Token.find(
            name='github',
            user=request.user
        )
        # API URL: https://api.github.com/user/repos
        resp = oauth.github.get('user/repos', token=token.to_token())
        resp.raise_for_status()
        return resp.json()

In this case, we need a place to store the access token in order to use
it later. Usually we will save the token into database. In the previous
**Routes for Authorization** ``authorize`` part, we can save the token into
database.


Design Database
~~~~~~~~~~~~~~~

It is possible to share one database table for both OAuth 1.0 token and
OAuth 2.0 token. It is also good to use different database tables for
OAuth 1.0 and OAuth 2.0.

In the above example, we are using two tables. Here are some hints on
how to design the database::

    class OAuth1Token(Model):
        name = String(length=40)
        oauth_token = String(length=200)
        oauth_token_secret = String(length=200)
        user = ForeignKey(User)

        def to_token(self):
            return dict(
                oauth_token=self.access_token,
                oauth_token_secret=self.alt_token,
            )

    class OAuth2Token(Model):
        name = String(length=40)
        token_type = String(length=40)
        access_token = String(length=200)
        refresh_token = String(length=200)
        expires_at = PositiveIntegerField()
        user = ForeignKey(User)

        def to_token(self):
            return dict(
                access_token=self.access_token,
                token_type=self.token_type,
                refresh_token=self.refresh_token,
                expires_at=self.expires_at,
            )


And then we can save user's access token into database when user was redirected
back to our ``authorize`` page.


Fetch User OAuth Token
~~~~~~~~~~~~~~~~~~~~~~

You can always pass a ``token`` parameter to the remote application request
methods, like::

    token = OAuth1Token.find(name='twitter', user=request.user)
    oauth.twitter.get(url, token=token)
    oauth.twitter.post(url, token=token)
    oauth.twitter.put(url, token=token)
    oauth.twitter.delete(url, token=token)

    token = OAuth2Token.find(name='github', user=request.user)
    oauth.github.get(url, token=token)
    oauth.github.post(url, token=token)
    oauth.github.put(url, token=token)
    oauth.github.delete(url, token=token)

However, it is not a good practice to query the token database in every request
function. Authlib provides a way to fetch current user's token automatically for
you, just ``register`` with ``fetch_token`` function::

    def fetch_twitter_token(request):
        token = OAuth1Token.find(
            name='twitter',
            user=request.user
        )
        return token.to_token()

    def fetch_github_token(request):
        token = OAuth2Token.find(
            name='github',
            user=request.user
        )
        return token.to_token()

    # we can registry this ``fetch_token`` with oauth.register
    oauth.register(
        'twitter',
        # ...
        fetch_token=fetch_twitter_token,
    )
    oauth.register(
        'github',
        # ...
        fetch_token=fetch_github_token,
    )

Not good enough. In this way, you have to write ``fetch_token`` for every
remote application. There is also a shared way to fetch token::

    def fetch_token(name, request):
        if name in OAUTH1_SERVICES:
            model = OAuth1Token
        else:
            model = OAuth2Token

        token = model.find(
            name=name,
            user=request.user
        )
        return token.to_token()

    # initialize OAuth registry with this fetch_token function
    oauth = OAuth(fetch_token=fetch_token)

Now, developers don't have to pass a ``token`` in the HTTP requests,
instead, they can pass the ``request``::

    def get_twitter_tweets(request):
        resp = oauth.twitter.get('statuses/user_timeline.json', request=request)
        resp.raise_for_status()
        return resp.json()


.. note:: Flask is different, you don't need to pass the ``request`` either.


OAuth 2.0 Enhancement
---------------------

OAuth 1.0 is a protocol, while OAuth 2.0 is a framework. There are so many
features in OAuth 2.0 than OAuth 1.0. This section is designed for
OAuth 2.0 specially.


Auto Update Token
~~~~~~~~~~~~~~~~~

In OAuth 1.0, access token never expires. But in OAuth 2.0, token MAY expire. If
there is a ``refresh_token`` value, Authlib will auto update the access token if
it is expired.

We do this by passing a ``update_token`` function to ``OAuth`` registry::

    def update_token(name, token, refresh_token=None, access_token=None):
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

    oauth = OAuth(update_token=update_token)

In this way, OAuth 2.0 integration will update expired token automatically. There is
also a **signal** way to update token. Checkout the frameworks documentation.


OAuth 2.0 Code Challenge
~~~~~~~~~~~~~~~~~~~~~~~~

Adding ``code_challenge`` provided by :ref:`specs/rfc7636` is simple. You
register your remote app with a ``code_challenge_method`` in ``client_kwargs``::

    oauth.register(
        'example',
        client_id='Example Client ID',
        client_secret='Example Client Secret',
        access_token_url='https://example.com/oauth/access_token',
        authorize_url='https://example.com/oauth/authorize',
        api_base_url='https://api.example.com/',
        client_kwargs={'code_challenge_method': 'S256'},
    )

Note, the only supported ``code_challenge_method`` is ``S256``.


Compliance Fix for OAuth 2.0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For non standard OAuth 2.0 service, you can pass a ``compliance_fix`` when
``.register``. For example, Slack has a compliance problem, we can construct
a method to fix the requests session::

    def slack_compliance_fix(session):
        def _fix(resp):
            resp.raise_for_status()
            token = resp.json()
            # slack returns no token_type
            token['token_type'] = 'Bearer'
            resp._content = to_unicode(json.dumps(token)).encode('utf-8')
            return resp
        session.register_compliance_hook('access_token_response', _fix)

Then pass this ``slack_compliance_fix`` into ``.register`` parameters::

    oauth.register(
        'slack',
        client_id='...',
        client_secret='...',
        ...,
        compliance_fix=slack_compliance_fix,
        ...
    )

Find all the available compliance hooks at :ref:`compliance_fix_oauth2`.


OpenID Connect & UserInfo
-------------------------

When logging in with OpenID Connect, "access_token" is not what developers
want. Instead, what developers want is **user info**, Authlib wrap it with
:class:`~authlib.oidc.core.UserInfo`.

There are two ways to fetch **userinfo** from 3rd party providers. If the
provider supports OpenID Connect, we can get the user info from the returned
``id_token``.


userinfo_endpoint
~~~~~~~~~~~~~~~~~

Passing a ``userinfo_endpoint`` when ``.register`` remote client::

    oauth.register(
        'google',
        client_id='...',
        client_secret='...',
        userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    )

And later, when the client has obtained the access token, we can call::

    def authorize(request):
        token = oauth.google.authorize_access_token(request)
        user = oauth.google.userinfo(token=token)
        return '...'


Parsing ``id_token``
~~~~~~~~~~~~~~~~~~~~

For OpenID Connect provider, when ``.authorize_access_token``, the provider
will include a ``id_token`` in the response. This ``id_token`` contains the
``UserInfo`` we need so that we don't have to fetch userinfo endpoint again.

The ``id_token`` is a JWT, with Authlib :ref:`jwt_guide`, we can decode it
easily. Frameworks integrations will handle it automatically if configurations
are correct.

A simple solution is to provide the OpenID Connect Discovery Endpoint::

    oauth.register(
        'google',
        client_id='...',
        client_secret='...',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

The discovery endpoint provides all the information we need so that we don't
have to add ``authorize_url`` and ``access_token_url``.

Check out our client example: https://github.com/authlib/demo-oauth-client

But if there is no discovery endpoint, developers MUST add all the missing information
themselves::

* authorize_url
* access_token_url
* jwks_uri

This ``jwks_uri`` is the URL to get provider's public JWKs. Developers MAY also
provide the value of ``jwks`` instead of ``jwks_uri``::

    oauth.register(
        'google',
        client_id='...',
        client_secret='...',
        access_token_url='https://example.com/oauth/access_token',
        authorize_url='https://example.com/oauth/authorize',
        jwks={"keys": [...]}
    )
