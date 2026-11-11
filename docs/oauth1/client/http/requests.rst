.. _requests_oauth1_client:

OAuth 1.0 for Requests
======================

.. meta::
    :description: An OAuth 1.0 Client implementation for Python requests,
        powered by Authlib.

.. module:: authlib.integrations.requests_client
    :noindex:

Requests is a very popular HTTP library for Python. Authlib enables OAuth 1.0
for Requests with its :class:`OAuth1Session` and :class:`OAuth1Auth`.


OAuth1Session
~~~~~~~~~~~~~

The requests integration follows our common guide of :ref:`OAuth 1 Session <oauth_1_session>`.
Follow the documentation in :ref:`OAuth 1 Session <oauth_1_session>` instead.

OAuth1Auth
~~~~~~~~~~

It is also possible to use :class:`OAuth1Auth` directly with requests.
After we obtained access token from an OAuth 1.0 provider, we can construct
an ``auth`` instance for requests:

.. invisible-code-block: python

    token = provider.issue_token("YOUR-CLIENT-ID")
    oauth_token = token["oauth_token"]
    oauth_token_secret = token["oauth_token_secret"]

.. code-block:: python

    auth = OAuth1Auth(
        client_id='YOUR-CLIENT-ID',
        client_secret='YOUR-CLIENT-SECRET',
        token=oauth_token,
        token_secret=oauth_token_secret,
    )
    url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    resp = requests.get(url, auth=auth)

.. invisible-code-block: python

    assert resp.status_code == 200, resp.text
