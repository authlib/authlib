.. _oauth_client:

Client
======

.. meta::
    :description: Python OAuth 2.0 Client implementations with requests, HTTPX,
        Flask, Django and Starlette, powered by Authlib.

Authlib provides OAuth 2.0 client implementations for two distinct use cases:

**HTTP Clients** — your Python code fetches tokens and calls APIs directly.
Suitable for scripts, CLIs, service-to-service communication::

    from authlib.integrations.requests_client import OAuth2Session

    client = OAuth2Session(client_id, client_secret)
    token = client.fetch_token(token_endpoint, ...)
    resp = client.get('https://api.example.com/data')

**Web Clients** — your web application delegates authentication to an OAuth 2.0
provider. Works with any provider: well-known services (GitHub, Google…) or
your own authorization server. Integrations for Flask, Django, Starlette and
FastAPI::

    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)
    github = oauth.register('github', {...})

    @app.route('/login')
    def login():
        return github.authorize_redirect(url_for('authorize', _external=True))

.. toctree::
    :maxdepth: 2

    http/index
    web/index
