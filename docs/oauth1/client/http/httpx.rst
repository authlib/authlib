.. _httpx_oauth1_client:

OAuth 1.0 for HTTPX
===================

.. meta::
    :description: An OAuth 1.0 Client implementation for HTTPX,
        powered by Authlib.

.. module:: authlib.integrations.httpx_client
    :noindex:

HTTPX is a next-generation HTTP client for Python. Authlib enables OAuth 1.0
for HTTPX with:

* :class:`OAuth1Client`
* :class:`AsyncOAuth1Client`

.. note:: HTTPX is still in its "alpha" stage, use it with caution.

HTTPX OAuth 1.0
---------------

There are three steps in OAuth 1 to obtain an access token:

1. fetch a temporary credential
2. visit the authorization page
3. exchange access token with the temporary credential

It shares a common API design with :ref:`requests_client`.

Read the common guide of :ref:`OAuth 1 Session <oauth_1_session>` to understand the whole OAuth
1.0 flow.


Async OAuth 1.0
---------------

The async version of :class:`AsyncOAuth1Client` works the same as
:ref:`OAuth 1 Session <oauth_1_session>`, except that we need to add ``await`` when
required::

    # fetching request token
    request_token = await client.fetch_request_token(request_token_url)

    # fetching access token
    access_token = await client.fetch_access_token(access_token_url)

    # normal requests
    await client.get(...)
    await client.post(...)
    await client.put(...)
    await client.delete(...)
