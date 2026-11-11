Register Grants
===============

.. meta::
    :description: Register Authorization Code Grant, Implicit Grant,
        Resource Owner Password Credentials Grant, Client Credentials Grant
        and Refresh Token Grant into Django OAuth 2.0 provider.

.. module:: authlib.oauth2.rfc6749.grants
    :noindex:

There are four grant types defined by RFC 6749, you can also create your own
extended grant. Register the supported grant types to the authorization server.

.. _django_oauth2_code_grant:

Authorization Code Grant
------------------------

Authorization Code Grant is a very common grant type, it is supported by almost
every OAuth 2 providers. It uses an authorization code to exchange access
token. In this case, we need a place to store the authorization code. It can be
kept in a database or a cache like redis. Here is an example of database
**AuthorizationCode**:

.. code-block:: python

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
        issued_at = IntegerField(null=False, default=now_timestamp)

        def is_expired(self):
            return self.issued_at + 300 < time.time()

        def get_redirect_uri(self):
            return self.redirect_uri

        def get_scope(self):
            return self.scope or ''

Implement the missing methods of
:class:`~authlib.oauth2.rfc6749.AuthorizationCodeMixin`.

Later, you can use this ``AuthorizationCode`` database model to handle ``authorization_code``
grant type. Here is how:

.. code-block:: python

    from authlib.oauth2.rfc6749 import grants
    from authlib.common.security import generate_token

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.payload.redirect_uri,
                response_type=request.payload.response_type,
                scope=request.scope,
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

Public clients, such as mobile or browser applications, use ``none``. To
accept them, add ``none`` in the subclass, and register the ``CodeChallenge``
extension of :ref:`specs/rfc7636`. This extension requires PKCE for public
clients:

.. code-block:: python

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none']

        # ... the methods of the previous example

Reused Codes
~~~~~~~~~~~~

A code can be exchanged only once. When the grant does not find a code, it
denies the request with ``invalid_grant``. Per :rfc:`6749#section-4.1.2`, if
the code was already used, the server should also revoke the tokens issued
with it. The grant calls
:meth:`~AuthorizationCodeGrant.revoke_authorization_code_tokens` with the code
string and the client before it denies the request. By default, this method
does nothing.

To revoke the tokens, link each token to its code. For instance, add an
``authorization_code`` field to the ``OAuth2Token`` model, and fill it in
``save_token``. ``request.authorization_code`` is the code being exchanged.
A token issued by the refresh token grant takes the code of the previous
token, ``request.refresh_token``:

.. code-block:: python

    from authlib.integrations.django_oauth2 import AuthorizationServer

    def get_authorization_code(request):
        if request.authorization_code:
            return request.authorization_code.code

        if request.refresh_token:
            return request.refresh_token.authorization_code

        return None

    class MyAuthorizationServer(AuthorizationServer):
        def save_token(self, token, request):
            token = {**token, "authorization_code": get_authorization_code(request)}
            return super().save_token(token, request)

Then revoke the tokens that carry the code:

.. code-block:: python

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        # ... the methods of the previous example

        def revoke_authorization_code_tokens(self, code, client):
            OAuth2Token.objects.filter(authorization_code=code).update(revoked=True)

The codes can be stored anywhere, for instance in a database or in a cache.
A used code can be deleted, or kept with a ``used`` flag. If it is kept,
``query_authorization_code`` must not return it.

Two requests that exchange the same code at the same time can both get a
token. To prevent it, lock the code while it is exchanged, for instance with
``SELECT ... FOR UPDATE`` in ``query_authorization_code``.

Implicit Grant
--------------

The implicit grant type is usually used in a browser, when resource
owner granted the access, access token is issued in the redirect URI,
there is no missing implementation, which means it can be easily registered
with:

.. code-block:: python

    from authlib.oauth2.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ImplicitGrant)

The client does not authenticate, because the implicit flow does not use the
token endpoint. Its ``token_endpoint_auth_method`` does not matter.

Resource Owner Password Credentials Grant
-----------------------------------------

Resource owner uses their username and password to exchange an access token,
this grant type should be used only when the client is trustworthy, implement
it with a subclass of :class:`ResourceOwnerPasswordCredentialsGrant`:

.. code-block:: python

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
You can add more in the subclass:

.. code-block:: python

    class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            'client_secret_basic', 'client_secret_post'
        ]

Client Credentials Grant
------------------------

Client credentials grant type can access public resources and the
client's creator's resources. It can be easily registered with:

.. code-block:: python

    from authlib.oauth2.rfc6749 import grants

    # register it to grant endpoint
    server.register_grant(grants.ClientCredentialsGrant)

Default allowed :ref:`client_auth_methods`: ``client_secret_basic``.
You can add more in the subclass:

.. code-block:: python

    class ClientCredentialsGrant(grants.ClientCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            'client_secret_basic', 'client_secret_post'
        ]

Refresh Token Grant
-------------------

Many OAuth 2 providers haven't implemented refresh token endpoint. Authlib
provides it as a grant type, implement it with a subclass of
:class:`RefreshTokenGrant`. The server issues refresh tokens only when
``refresh_token_generator`` is set in ``AUTHLIB_OAUTH2_PROVIDER``:

.. code-block:: python

    from authlib.oauth2.rfc6749 import grants

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        def authenticate_refresh_token(self, refresh_token):
            try:
                item = OAuth2Token.objects.get(refresh_token=refresh_token)
            except OAuth2Token.DoesNotExist:
                return None

            # if refresh tokens expire, also check the expiration here
            if not item.is_revoked():
                return item

        def authenticate_user(self, credential):
            return credential.user

        def revoke_old_credential(self, credential):
            credential.revoked = True
            credential.save()

    # register it to grant endpoint
    server.register_grant(RefreshTokenGrant)

Default allowed :ref:`client_auth_methods`: ``client_secret_basic``.
You can add more in the subclass:

.. code-block:: python

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            'client_secret_basic', 'client_secret_post'
        ]

By default, RefreshTokenGrant will not issue a ``refresh_token`` in the token
response. Developers can change this behavior with:

.. code-block:: python

    class RefreshTokenGrant(grants.RefreshTokenGrant):
        INCLUDE_NEW_REFRESH_TOKEN = True

Custom Grant Types
------------------

It is also possible to create your own grant types. In Authlib, a **Grant**
supports two endpoints:

1. Authorization Endpoint: which can handle requests with ``response_type``.
2. Token Endpoint: which is the endpoint to issue tokens.

Creating a custom grant type with **BaseGrant**:

.. code-block:: python

    from authlib.oauth2.rfc6749.grants import (
        BaseGrant, AuthorizationEndpointMixin, TokenEndpointMixin
    )

    class MyCustomGrant(BaseGrant, AuthorizationEndpointMixin, TokenEndpointMixin):
        GRANT_TYPE = 'custom-grant-type-name'

        def validate_authorization_request(self):
            # only needed if using AuthorizationEndpointMixin
            ...

        def create_authorization_response(self, redirect_uri, grant_user):
            # only needed if using AuthorizationEndpointMixin
            # return an AuthorizationResponse(redirect_uri, params)
            ...

        def validate_token_request(self):
            # only needed if using TokenEndpointMixin
            ...

        def create_token_response(self):
            # only needed if using TokenEndpointMixin
            # return a JsonResponse(token)
            ...

For a better understanding, you can read the source code of the built-in
grant types. And there are extended grant types defined by other specs:

1. :ref:`jwt_grant_type`


Grant Extensions
----------------

Grant can accept extensions. Developers can pass extensions when registering
grant. For instance, there is ``CodeChallenge`` extension in Authlib:

.. code-block:: python

    server.register_grant(AuthorizationCodeGrant, [CodeChallenge()])

Learn more about ``CodeChallenge`` at :ref:`specs/rfc7636`.

An extension that adds parameters to the authorization request declares them,
with their JSON types. The server rejects a request that repeats one of them:

.. code-block:: python

    class MyExtension:
        def __call__(self, grant):
            grant.register_authorization_parameters({"my_parameter": str})

.. invisible-code-block: python

    import base64
    from urllib.parse import urlencode

    create_tables()
    user = User.objects.create_user(username="alice", password="secret")
    OAuth2Client.objects.create(
        user=user,
        client_id="client-id",
        client_secret="client-secret",
        grant_type="password refresh_token",
        scope="profile",
        token_endpoint_auth_method="client_secret_basic",
    )
    authorization = "Basic " + base64.b64encode(b"client-id:client-secret").decode()

    def token_request(data):
        request = request_factory.post(
            "/oauth/token",
            data=urlencode(data),
            content_type="application/x-www-form-urlencoded",
            HTTP_AUTHORIZATION=authorization,
        )
        response = server.create_token_response(request)
        return response.status_code, json.loads(response.content)

    status, token = token_request(
        {"grant_type": "password", "username": "alice", "password": "secret"}
    )
    assert status == 200, token

    data = {"grant_type": "refresh_token", "refresh_token": token["refresh_token"]}
    status, body = token_request(data)
    assert status == 200, body

    status, body = token_request(data)
    assert status == 400, "the old refresh token is still accepted"
