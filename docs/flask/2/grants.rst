Register Grants
===============

.. module:: authlib.oauth2.rfc6749.grants
    :noindex:

There are four grant types defined by RFC6749, you can also create your own
extended grant. Register the supported grant types to the authorization server.

.. _flask_oauth2_code_grant:

Authorization Code Grant
------------------------

Authorization Code Grant is a very common grant type, it is supported by almost
every OAuth 2 providers. It uses an authorization code to exchange access
tokens. In this case, we need a place to store the authorization code. It can
be kept in a database or a cache like redis. Here is a SQLAlchemy mixin for
**AuthorizationCode**::

    from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin

    class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
        )
        user = db.relationship('User')

Implement this grant by subclassing :class:`AuthorizationCodeGrant`::

    from authlib.oauth2.rfc6749 import grants

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.payload.scope,
                user_id=request.user.id,
            )
            db.session.add(auth_code)
            db.session.commit()
            return auth_code

        def query_authorization_code(self, code, client):
            item = AuthorizationCode.query.filter_by(
                code=code, client_id=client.client_id).first()
            if item and not item.is_expired():
                return item

        def delete_authorization_code(self, authorization_code):
            db.session.delete(authorization_code)
            db.session.commit()

        def authenticate_user(self, authorization_code):
            return User.query.get(authorization_code.user_id)

    # register it to grant endpoint
    server.register_grant(AuthorizationCodeGrant)

.. note:: AuthorizationCodeGrant is the most complex grant.

Default allowed :ref:`client_auth_methods` are:

1. client_secret_basic
2. client_secret_post
3. none

You can change it in the subclass, e.g. remove the ``none`` authentication method::

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

.. note:: This is important when you want to support OpenID Connect.

Implicit Grant
--------------

The implicit grant type is usually used in a browser, when resource
owner granted the access, an access token is issued in the redirect URI,
there is no missing implementation, which means it can be easily registered
with::

    from authlib.oauth2.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ImplicitGrant)

Implicit Grant is used by **public** clients which have no **client_secret**.
Default allowed :ref:`client_auth_methods`: ``none``.

Resource Owner Password Credentials Grant
-----------------------------------------

The resource owner uses its username and password to exchange an access
token. This grant type should be used only when the client is trustworthy;
implement it with a subclass of
:class:`ResourceOwnerPasswordCredentialsGrant`::

    from authlib.oauth2.rfc6749 import grants

    class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
        def authenticate_user(self, username, password):
            user = User.query.filter_by(username=username).first()
            if user.check_password(password):
                return user

    # register it to grant endpoint
    server.register_grant(PasswordGrant)


Default allowed :ref:`client_auth_methods`: ``client_secret_basic``.
You can add more in the subclass::

    class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            'client_secret_basic', 'client_secret_post'
        ]

Client Credentials Grant
------------------------

Client credentials grant type can access public resources and MAYBE the
client's creator's resources, depending on how you issue tokens to this
grant type. It can be easily registered with::

    from authlib.oauth2.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ClientCredentialsGrant)

Default allowed :ref:`client_auth_methods`: ``client_secret_basic``.
You can add more in the subclass::

    class ClientCredentialsGrant(grants.ClientCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            'client_secret_basic', 'client_secret_post'
        ]

Refresh Token Grant
-------------------

Many OAuth 2 providers do not implement a refresh token endpoint. Authlib
provides it as a grant type; implement it with a subclass of
:class:`RefreshTokenGrant`::

    from authlib.oauth2.rfc6749 import grants

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        def authenticate_refresh_token(self, refresh_token):
            item = Token.query.filter_by(refresh_token=refresh_token).first()
            # define is_refresh_token_valid by yourself
            # usually, you should check if refresh token is expired and revoked
            if item and item.is_refresh_token_valid():
                return item

        def authenticate_user(self, credential):
            return User.query.get(credential.user_id)

        def revoke_old_credential(self, credential):
            credential.revoked = True
            db.session.add(credential)
            db.session.commit()

    # register it to grant endpoint
    server.register_grant(RefreshTokenGrant)

Default allowed :ref:`client_auth_methods`: ``client_secret_basic``.
You can add more in the subclass::

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            'client_secret_basic', 'client_secret_post'
        ]

By default, RefreshTokenGrant will not issue a ``refresh_token`` in the token
response. Developers can change this behavior with::

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        INCLUDE_NEW_REFRESH_TOKEN = True

.. _flask_oauth2_custom_grant_types:

Custom Grant Types
------------------

It is also possible to create your own grant types. In Authlib, a **Grant**
supports two endpoints:

1. Authorization Endpoint: which can handle requests with ``response_type``.
2. Token Endpoint: which is the endpoint to issue tokens.

.. versionchanged:: v0.12
    Using ``AuthorizationEndpointMixin`` and ``TokenEndpointMixin`` instead of
    ``AUTHORIZATION_ENDPOINT=True`` and ``TOKEN_ENDPOINT=True``.

Creating a custom grant type with **BaseGrant**::

    from authlib.oauth2.rfc6749.grants import (
        BaseGrant, AuthorizationEndpointMixin, TokenEndpointMixin
    )


    class MyCustomGrant(BaseGrant, AuthorizationEndpointMixin, TokenEndpointMixin):
        GRANT_TYPE = 'custom-grant-type-name'

        def validate_authorization_request(self):
            # only needed if using AuthorizationEndpointMixin

        def create_authorization_response(self, grant_user):
            # only needed if using AuthorizationEndpointMixin

        def validate_token_request(self):
            # only needed if using TokenEndpointMixin

        def create_token_response(self):
            # only needed if using TokenEndpointMixin

For a better understanding, you can read the source code of the built-in
grant types. And there are extended grant types defined by other specs:

1. :ref:`jwt_grant_type`


.. _flask_oauth2_grant_extensions:

Grant Extensions
----------------

.. versionadded:: 0.10

Grants can accept extensions. Developers can pass extensions when registering
grants::

    authorization_server.register_grant(AuthorizationCodeGrant, [extension])

For instance, there is the ``CodeChallenge`` extension in Authlib::

    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])

Learn more about ``CodeChallenge`` at :ref:`specs/rfc7636`.
