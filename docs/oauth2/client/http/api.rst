Reference
=========

.. meta::
   :description: API references on Authlib OAuth 2.0 HTTP session clients.

Requests OAuth 2.0
------------------

.. module:: authlib.integrations.requests_client
   :no-index:

.. autoclass:: OAuth2Session
    :no-index:
    :members:
        register_client_auth_method,
        create_authorization_url,
        fetch_token,
        refresh_token,
        revoke_token,
        introspect_token,
        register_compliance_hook

.. autoclass:: OAuth2Auth
    :no-index:

.. autoclass:: AssertionSession
    :no-index:


HTTPX OAuth 2.0
---------------

.. module:: authlib.integrations.httpx_client
   :no-index:

.. autoclass:: OAuth2Auth
    :no-index:

.. autoclass:: OAuth2Client
    :no-index:
    :members:
        register_client_auth_method,
        create_authorization_url,
        fetch_token,
        refresh_token,
        revoke_token,
        introspect_token,
        register_compliance_hook

.. autoclass:: AsyncOAuth2Client
    :no-index:
    :members:
        register_client_auth_method,
        create_authorization_url,
        fetch_token,
        refresh_token,
        revoke_token,
        introspect_token,
        register_compliance_hook

.. autoclass:: AsyncAssertionClient
    :no-index:
