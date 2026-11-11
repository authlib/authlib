.. _oauth1_client:

Client
======

.. meta::
    :description: Python OAuth 1.0 Client implementations with requests, HTTPX2,
        Flask, Django and Starlette, powered by Authlib.

Authlib provides OAuth 1.0 client implementations for two distinct use cases:

**HTTP Clients** — your Python code fetches tokens and calls APIs directly.
Suitable for scripts, CLIs, service-to-service communication:

.. skip: next "summary of the flow of the next pages"

.. code-block:: python

    from authlib.integrations.requests_client import OAuth1Session

    client = OAuth1Session(client_id, client_secret, redirect_uri=redirect_uri)
    request_token = client.fetch_request_token(request_token_url)
    # ... redirect user, then:
    token = client.fetch_access_token(access_token_url)
    resp = client.get('https://api.example.com/data')

**Web Clients** — your web application delegates authentication to an OAuth 1.0
provider. Works with any OAuth 1.0 provider (Twitter, or your own). Integrations
for Flask, Django, Starlette and FastAPI:

.. code-block:: python

    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)
    twitter = oauth.register(
        'twitter',
        client_id='...',
        client_secret='...',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
    )

    @app.route('/login')
    def login():
        return twitter.authorize_redirect(url_for('authorize', _external=True))

.. toctree::
    :maxdepth: 2

    http/index
    web/index
