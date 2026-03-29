.. _httpx_client:


OAuth 2.0 for HTTPX
===================

.. meta::
    :description: An OAuth 2.0 Client implementation for a next
        generation HTTP client for Python, including support for OpenID Connect
        and service account, powered by Authlib.

.. module:: authlib.integrations.httpx_client
    :noindex:

HTTPX is a next-generation HTTP client for Python. Authlib enables OAuth 2.0
for HTTPX with its async versions:

* :class:`OAuth2Client`
* :class:`AssertionClient`
* :class:`AsyncOAuth2Client`
* :class:`AsyncAssertionClient`

.. note:: HTTPX is still in its "alpha" stage, use it with caution.

HTTPX OAuth 2.0
---------------

In :ref:`OAuth 2 Session <oauth_2_session>`, there are many grant types, including:

1. Authorization Code Flow
2. Implicit Flow
3. Password Flow
4. Client Credentials Flow

And also, Authlib supports non Standard OAuth 2.0 providers via Compliance Fix.

Read the common guide of :ref:`OAuth 2 Session <oauth_2_session>` to understand the whole OAuth
2.0 flow.

Using ``client_secret_jwt`` in HTTPX
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here is how you could register and use ``client_secret_jwt`` client
authentication method for HTTPX::

    from authlib.integrations.httpx_client import AsyncOAuth2Client
    from authlib.oauth2.rfc7523 import ClientSecretJWT

    client = AsyncOAuth2Client(
        'your-client-id', 'your-client-secret',
        token_endpoint_auth_method='client_secret_jwt'
    )
    token_endpoint = 'https://example.com/oauth/token'
    client.register_client_auth_method(ClientSecretJWT(token_endpoint))
    client.fetch_token(token_endpoint)

The ``ClientSecretJWT`` is provided by :ref:`specs/rfc7523`.


Using ``private_key_jwt`` in HTTPX
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here is how you could register and use ``private_key_jwt`` client
authentication method for HTTPX::

    from authlib.integrations.httpx_client import AsyncOAuth2Client
    from authlib.oauth2.rfc7523 import PrivateKeyJWT

    with open('your-private-key.pem', 'rb') as f:
        private_key = f.read()

    client = AsyncOAuth2Client(
        'your-client-id', private_key,
        token_endpoint_auth_method='private_key_jwt',
    )
    token_endpoint = 'https://example.com/oauth/token'
    client.register_client_auth_method(PrivateKeyJWT(token_endpoint))
    client.fetch_token(token_endpoint)

The ``PrivateKeyJWT`` is provided by :ref:`specs/rfc7523`.


Async OAuth 2.0
---------------

The async version of :class:`AsyncOAuth2Client` works the same as
:ref:`OAuth 2 Session <oauth_2_session>`, except that we need to add ``await`` when
required::

    # fetching access token
    token = await client.fetch_token(token_endpoint, ...)

    # normal requests
    await client.get(...)
    await client.post(...)
    await client.put(...)
    await client.delete(...)


Auto Update Token
~~~~~~~~~~~~~~~~~

The :class:`AsyncOAuth2Client` also supports ``update_token`` parameter,
the ``update_token`` can either be sync and async. For instance::

    async def update_token(token, refresh_token=None, access_token=None):
        if refresh_token:
            item = await OAuth2Token.find(name=name, refresh_token=refresh_token)
        elif access_token:
            item = await OAuth2Token.find(name=name, access_token=access_token)
        else:
            return

        # update old token
        item.access_token = token['access_token']
        item.refresh_token = token.get('refresh_token')
        item.expires_at = token['expires_at']
        await item.save()

Then pass this ``update_token`` into ``AsyncOAuth2Client``.


Async Service Account
---------------------

:class:`AsyncAssertionClient` is the async version for Assertion Framework of
OAuth 2.0 Authorization Grants. It is also know as service account. A configured
``AsyncAssertionClient`` will handle token authorization automatically,
which means you can just use it.

Take Google Service Account as an example, with the information in your
service account JSON configure file::

    import json
    from authlib.integrations.httpx_client import AsyncAssertionClient

    with open('MyProject-1234.json') as f:
        conf = json.load(f)

    token_uri = conf['token_uri']
    header = {'alg': 'RS256'}
    key_id = conf.get('private_key_id')
    if key_id:
        header['kid'] = key_id

    # Google puts scope in payload
    claims = {'scope': scope}

    async def main():
        client = AsyncAssertionClient(
            token_endpoint=token_uri,
            issuer=conf['client_email'],
            audience=token_uri,
            claims=claims,
            subject=None,
            key=conf['private_key'],
            header=header,
        )
        resp = await client.get(...)
        resp = await client.post(...)


Close Client Hint
-----------------

Developers SHOULD **close** a HTTPX Session when the jobs are done. You
can call ``.close()`` manually, or use a ``with`` context to automatically
close the session::

    client = OAuth2Client(client_id, client_secret)
    client.get(url)
    client.close()

    with OAuth2Client(client_id, client_secret) as client:
        client.get(url)

For **async** OAuth Client, use ``await client.close()``::

    client = AsyncOAuth2Client(client_id, client_secret)
    await client.get(url)
    await client.close()

    async with AsyncOAuth2Client(client_id, client_secret) as client:
        await client.get(url)

Our :ref:`frameworks_clients` will close every session automatically, no need
to worry.
