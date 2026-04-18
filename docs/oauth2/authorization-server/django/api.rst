Reference
=========

This part of the documentation covers the interface of Django OAuth 2.0
Server.

.. module:: authlib.integrations.django_oauth2

.. autoclass:: AuthorizationServer
    :members:
        register_grant,
        register_endpoint,
        get_consent_grant,
        create_authorization_response,
        create_token_response,
        create_endpoint_response

.. autoclass:: ResourceProtector
    :member-order: bysource
    :members:

.. autoclass:: BearerTokenValidator
    :member-order: bysource
    :members:

.. autoclass:: RevocationEndpoint
    :member-order: bysource
    :members:


.. data:: client_authenticated

    Signal when client is authenticated

.. data:: token_revoked

    Signal when token is revoked

.. data:: token_authenticated

    Signal when token is authenticated
