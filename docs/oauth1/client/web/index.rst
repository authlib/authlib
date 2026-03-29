.. _frameworks_oauth1_clients:

Web Clients
===========

.. module:: authlib.integrations
    :noindex:

This documentation covers OAuth 1.0 integrations for Python Web Frameworks like:

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

1. :class:`flask_client.OAuth` for :ref:`flask_oauth1_client`
2. :class:`django_client.OAuth` for :ref:`django_oauth1_client`
3. :class:`starlette_client.OAuth` for :ref:`starlette_oauth1_client`

The common use case for OAuth is authentication, e.g. let your users log in
with Twitter.

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
:ref:`OAuth 1 Session <oauth_1_session>`. If you are using ``RSA-SHA1`` signature method::

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


Accessing OAuth Resources
-------------------------

.. note::

    If your application ONLY needs login via 3rd party services like
    Twitter to login, you DON'T need to create the token database.

There are also chances that you need to access your user's 3rd party
OAuth provider resources. For instance, you want to display the logged
in user's twitter time line. You will use **access token** to fetch
the resources::

    def get_twitter_tweets(request):
        token = OAuth1Token.find(
            name='twitter',
            user=request.user
        )
        # API URL: https://api.twitter.com/1.1/statuses/user_timeline.json
        resp = oauth.twitter.get('statuses/user_timeline.json', token=token.to_token())
        resp.raise_for_status()
        return resp.json()

In this case, we need a place to store the access token in order to use
it later. Usually we will save the token into database. In the previous
**Routes for Authorization** ``authorize`` part, we can save the token into
database.


Design Database
~~~~~~~~~~~~~~~

Here are some hints on how to design the OAuth 1.0 token database::

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

However, it is not a good practice to query the token database in every request
function. Authlib provides a way to fetch current user's token automatically for
you, just ``register`` with ``fetch_token`` function::

    def fetch_twitter_token(request):
        token = OAuth1Token.find(
            name='twitter',
            user=request.user
        )
        return token.to_token()

    # we can registry this ``fetch_token`` with oauth.register
    oauth.register(
        'twitter',
        # ...
        fetch_token=fetch_twitter_token,
    )

There is also a shared way to fetch token::

    def fetch_token(name, request):
        token = OAuth1Token.find(
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

.. toctree::
    :maxdepth: 1

    flask
    django
    starlette
    fastapi
    api
