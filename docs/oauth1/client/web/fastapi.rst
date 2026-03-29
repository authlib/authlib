.. _fastapi_oauth1_client:

FastAPI Integration
===================

.. meta::
    :description: Use Authlib built-in Starlette integrations to build
        OAuth 1.0 clients for FastAPI.

.. module:: authlib.integrations.starlette_client
    :noindex:

FastAPI_ is a modern, fast (high-performance), web framework for building
APIs with Python 3.6+ based on standard Python type hints. It is built on
top of **Starlette**, that means most of the code looks similar with
Starlette code. You should first read documentation of:

1. :ref:`frameworks_oauth1_clients`
2. :ref:`starlette_oauth1_client`

Here is how you would create a FastAPI application::

    from fastapi import FastAPI
    from starlette.middleware.sessions import SessionMiddleware

    app = FastAPI()
    # we need this to save temporary credential in session
    app.add_middleware(SessionMiddleware, secret_key="some-random-string")

Since Authlib starlette requires using ``request`` instance, we need to
expose that ``request`` to Authlib. According to the documentation on
`Using the Request Directly <https://fastapi.tiangolo.com/advanced/using-request-directly/>`_::

    from starlette.requests import Request

    @app.get("/login/twitter")
    async def login_via_twitter(request: Request):
        redirect_uri = request.url_for('auth_via_twitter')
        return await oauth.twitter.authorize_redirect(request, redirect_uri)

    @app.get("/auth/twitter")
    async def auth_via_twitter(request: Request):
        token = await oauth.twitter.authorize_access_token(request)
        # do something with the token
        return dict(token)

.. _FastAPI: https://fastapi.tiangolo.com/

We have a blog post about how to create Twitter login in FastAPI:

https://blog.authlib.org/2020/fastapi-twitter-login
