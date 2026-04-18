Reference
=========

This part of the documentation covers the interface of Flask OAuth 2.0
Server.

.. module:: authlib.integrations.flask_oauth2

.. autoclass:: AuthorizationServer
    :members:
        register_grant,
        register_endpoint,
        create_bearer_token_generator,
        get_consent_grant,
        create_authorization_response,
        create_token_response,
        create_endpoint_response

.. autoclass:: ResourceProtector
    :member-order: bysource
    :members:

.. data:: current_token

    Routes protected by :class:`ResourceProtector` can access current token
    with this variable::

        from authlib.integrations.flask_oauth2 import current_token

        @require_oauth
        @app.route('/user_id')
        def user_id():
            # current token instance of the OAuth Token model
            return current_token.user_id

.. data:: client_authenticated

    Signal when client is authenticated

.. data:: token_revoked

    Signal when token is revoked

.. data:: token_authenticated

    Signal when token is authenticated


SQLAlchemy Helper Functions
---------------------------

.. warning:: We will drop ``sqla_oauth2`` module in version 1.0.

.. module:: authlib.integrations.sqla_oauth2

.. autofunction:: create_query_client_func

.. autofunction:: create_save_token_func

.. autofunction:: create_query_token_func

.. autofunction:: create_revocation_endpoint

.. autofunction:: create_bearer_token_validator
