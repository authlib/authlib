.. _fastapi_client:

FastAPI OAuth Client
====================

.. meta::
    :description: Use Authlib built-in Starlette integrations to build
        OAuth 1.0, OAuth 2.0 and OpenID Connect clients for FastAPI.

.. module:: authlib.integrations.starlette_client
    :noindex:

FastAPI_ is a modern, fast (high-performance), web framework for building
APIs with Python 3.6+ based on standard Python type hints. It is build on
top of **Starlette**, that means most of the code looks similar with
Starlette code. You should first read documentation of:

1. :ref:`frameworks_clients`
2. :ref:`starlette_client`

Here is how you would create a FastAPI application::

    from fastapi import FastAPI
    from starlette.middleware.sessions import SessionMiddleware

    app = FastAPI()
    # we need this to save temporary code & state in session
    app.add_middleware(SessionMiddleware, secret_key="some-random-string")

Since Authlib starlette requires using ``request`` instance, we need to
expose that ``request`` to Authlib. According to the documentation on
`Using the Request Directly <https://fastapi.tiangolo.com/advanced/using-request-directly/>`_::

    from starlette.requests import Request

    @app.get("/login/google")
    async def login_via_google(request: Request):
        redirect_uri = request.url_for('auth_via_google')
        return await oauth.google.authorize_redirect(request, redirect_uri)

    @app.get("/auth/google")
    async def auth_via_google(request: Request):
        token = await oauth.google.authorize_access_token(request)
        user = token['userinfo']
        return dict(user)

.. _FastAPI: https://fastapi.tiangolo.com/

All other APIs are the same with Starlette.

FastAPI OAuth 1.0 Client
------------------------

We have a blog post about how to create Twitter login in FastAPI:

https://blog.authlib.org/2020/fastapi-twitter-login

FastAPI OAuth 2.0 Client
------------------------

We have a blog post about how to create Google login in FastAPI:

https://blog.authlib.org/2020/fastapi-google-login

