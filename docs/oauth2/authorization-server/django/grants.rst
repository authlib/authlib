Register Grants
===============

.. meta::
    :description: Register Authorization Code Grant, Implicit Grant,
        Resource Owner Password Credentials Grant, Client Credentials Grant
        and Refresh Token Grant into Django OAuth 2.0 provider.

.. module:: authlib.oauth2.rfc6749.grants
    :noindex:

There are four grant types defined by RFC6749, you can also create your own
extended grant. Register the supported grant types to the authorization server.

.. _django_oauth2_code_grant:

Authorization Code Grant
------------------------

Authorization Code Grant is a very common grant type, it is supported by almost
every OAuth 2 providers. It uses an authorization code to exchange access
token. In this case, we need a place to store the authorization code. It can be
kept in a database or a cache like redis. Here is an example of database
**AuthorizationCode**::

    from django.db.models import ForeignKey, CASCADE
    from django.contrib.auth.models import User
    from authlib.oauth2.rfc6749 import AuthorizationCodeMixin

    def now_timestamp():
        return int(time.time())

    class AuthorizationCode(Model, AuthorizationCodeMixin):
        user = ForeignKey(User, on_delete=CASCADE)
        client_id = CharField(max_length=48, db_index=True)
        code = CharField(max_length=120, unique=True, null=False)
        redirect_uri = TextField(default='', null=True)
        response_type = TextField(default='')
        scope = TextField(default='', null=True)
        auth_time = IntegerField(null=False, default=now_timestamp)

        def is_expired(self):
            return self.auth_time + 300 < time.time()

        def get_redirect_uri(self):
            return self.redirect_uri

        def get_scope(self):
            return self.scope or ''

        def get_auth_time(self):
            return self.auth_time

Note here, you **MUST** implement the missing methods of
:class:`~authlib.oauth2.rfc6749.AuthorizationCodeMixin` API interface.

Later, you can use this ``AuthorizationCode`` database model to handle ``authorization_code``
grant type. Here is how::

    from authlib.oauth2.rfc6749 import grants
    from authlib.common.security import generate_token

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                response_type=request.payload.response_type,
                scope=request.payload.scope,
                user=request.user,
            )
            auth_code.save()
            return auth_code

        def query_authorization_code(self, code, client):
            try:
                item = AuthorizationCode.objects.get(code=code, client_id=client.client_id)
            except AuthorizationCode.DoesNotExist:
                return None

            if not item.is_expired():
                return item

        def delete_authorization_code(self, authorization_code):
            authorization_code.delete()

        def authenticate_user(self, authorization_code):
            return authorization_code.user

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
owner granted the access, access token is issued in the redirect URI,
there is no missing implementation, which means it can be easily registered
with::

    from authlib.oauth2.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ImplicitGrant)

Implicit Grant is used by **public** client which has no **client_secret**.
Only allowed :ref:`client_auth_methods`: ``none``.

Resource Owner Password Credentials Grant
-----------------------------------------

Resource owner uses their username and password to exchange an access token,
this grant type should be used only when the client is trustworthy, implement
it with a subclass of :class:`ResourceOwnerPasswordCredentialsGrant`::

    from authlib.oauth2.rfc6749 import grants
    from django.contrib.auth.models import User

    class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
        def authenticate_user(self, username, password):
            try:
                user = User.objects.get(username=username)
                if user.check_password(password):
                    return user
            except User.DoesNotExist:
                return None

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

Client credentials grant type can access public resources and the
client's creator's resources. It can be easily registered with::

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

Many OAuth 2 providers haven't implemented refresh token endpoint. Authlib
provides it as a grant type, implement it with a subclass of
:class:`RefreshTokenGrant`::

    from authlib.oauth2.rfc6749 import grants

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        def authenticate_refresh_token(self, refresh_token):
            try:
                item = OAuth2Token.objects.get(refresh_token=refresh_token)
                if item.is_refresh_token_active():
                    return item
            except OAuth2Token.DoesNotExist:
                return None

        def authenticate_user(self, credential):
            return credential.user

        def revoke_old_credential(self, credential):
            credential.revoked = True
            credential.save()

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

Custom Grant Types
------------------

It is also possible to create your own grant types. In Authlib, a **Grant**
supports two endpoints:

1. Authorization Endpoint: which can handle requests with ``response_type``.
2. Token Endpoint: which is the endpoint to issue tokens.

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


Grant Extensions
----------------

Grant can accept extensions. Developers can pass extensions when registering
grant::

    server.register_grant(AuthorizationCodeGrant, [extension])

For instance, there is ``CodeChallenge`` extension in Authlib::

    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=False)])

Learn more about ``CodeChallenge`` at :ref:`specs/rfc7636`.
