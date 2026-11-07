.. _requests_client:


OAuth 2.0 for Requests
======================

.. meta::
    :description: An OAuth 2.0 Client implementation for Python requests,
        including support for OpenID Connect and service account, powered by Authlib.

.. module:: authlib.integrations.requests_client
    :noindex:

Requests is a very popular HTTP library for Python. Authlib enables OAuth 2.0
for Requests with its :class:`OAuth2Session` and :class:`AssertionSession`.


Requests OAuth 2.0
------------------

In :ref:`OAuth 2 Session <oauth_2_session>`, there are many grant types, including:

1. Authorization Code Flow
2. Implicit Flow
3. Password Flow
4. Client Credentials Flow

And also, Authlib supports non Standard OAuth 2.0 providers via Compliance Fix.

Follow the common guide of :ref:`OAuth 2 Session <oauth_2_session>` to find out how to use
requests integration of OAuth 2.0 flow.


Using ``client_secret_jwt`` in Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are **three default client authentication methods** defined for
``OAuth2Session``. But what if you want to use ``client_secret_jwt`` instead?
``client_secret_jwt`` is defined in RFC 7523, use it for Requests:

.. code-block:: python

    from authlib.integrations.requests_client import OAuth2Session
    from authlib.oauth2.rfc7523 import ClientSecretJWT

    token_endpoint = 'https://example.com/oauth/token'
    session = OAuth2Session(
        'your-client-id', 'your-client-secret',
        token_endpoint_auth_method=ClientSecretJWT(token_endpoint),
    )
    session.fetch_token(token_endpoint)

The ``ClientSecretJWT`` is provided by :ref:`specs/rfc7523`.

Using ``private_key_jwt`` in Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

What if you want to use ``private_key_jwt`` client authentication method,
here is the way with  ``PrivateKeyJWT`` for Requests:

.. skip: next "reads a private key file"

.. code-block:: python

    from authlib.integrations.requests_client import OAuth2Session
    from authlib.oauth2.rfc7523 import PrivateKeyJWT

    with open('your-private-key.pem', 'rb') as f:
        private_key = f.read()

    token_endpoint = 'https://example.com/oauth/token'
    session = OAuth2Session(
        'your-client-id', private_key,
        token_endpoint_auth_method=PrivateKeyJWT(token_endpoint),
    )
    session.fetch_token(token_endpoint)

The ``PrivateKeyJWT`` is provided by :ref:`specs/rfc7523`.


OAuth2Auth
~~~~~~~~~~

Already obtained access token? We can use :class:`OAuth2Auth` directly in
requests. But this OAuth2Auth can not refresh token automatically for you.
Here is how to use it in requests:

.. code-block:: python

    token = {'token_type': 'bearer', 'access_token': '....'}
    auth = OAuth2Auth(token)
    requests.get(url, auth=auth)


Requests OpenID Connect
-----------------------

OpenID Connect is built on OAuth 2.0. It is pretty simple to communicate with
an OpenID Connect provider via Authlib. With Authlib built-in OAuth 2.0 system
and JsonWebToken (JWT), parsing OpenID Connect ``id_token`` could be very easy.

Understand how it works with :ref:`oidc_session`.


Requests Service Account
------------------------

The Assertion Framework of OAuth 2.0 Authorization Grants is also known as
service account. With the implementation of :class:`AssertionSession`, we can
easily integrate with a "assertion" service.

Checking out an example of Google Service Account with :ref:`assertion_session`.


Close Session Hint
------------------

Close a Requests Session when the jobs are done. Call ``.close()``, or use a
``with`` context to close the session automatically:

.. code-block:: python

    session = OAuth2Session(client_id, client_secret, token=token)
    session.get(url)
    session.close()

    with OAuth2Session(client_id, client_secret, token=token) as session:
        session.get(url)


Mutual TLS Client Authentication
--------------------------------

With mutual TLS client authentication (:rfc:`RFC 8705 §2 <8705#section-2>`), the client
proves its identity with a TLS certificate. Authlib does not implement
:rfc:`8705`. Give the certificate to Requests with the ``cert`` attribute, and
use the ``none`` method, so that the client sends its ``client_id`` without a
secret:

.. code-block:: python

    session = OAuth2Session(client_id, token_endpoint_auth_method='none')
    session.cert = ('/path/to/client-cert.pem', '/path/to/client-key.pem')

If the server certificate is signed by a private CA, set ``session.verify`` to
the path of the CA bundle.
