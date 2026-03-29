Reference
=========

.. meta::
   :description: API references on Authlib OAuth 1.0 HTTP session clients.

Requests OAuth 1.0
------------------

.. module:: authlib.integrations.requests_client

.. autoclass:: OAuth1Session
    :members:
        create_authorization_url,
        fetch_request_token,
        fetch_access_token,
        parse_authorization_response

.. autoclass:: OAuth1Auth
    :members:


HTTPX OAuth 1.0
---------------

.. module:: authlib.integrations.httpx_client

.. autoclass:: OAuth1Auth
    :members:

.. autoclass:: OAuth1Client
    :members:
        create_authorization_url,
        fetch_request_token,
        fetch_access_token,
        parse_authorization_response

.. autoclass:: AsyncOAuth1Client
    :members:
        create_authorization_url,
        fetch_request_token,
        fetch_access_token,
        parse_authorization_response
