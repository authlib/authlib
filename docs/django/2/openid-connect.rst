.. _django_oidc_server:

Django OIDC Provider
====================

.. meta::
    :description: How to create an OpenID Connect server in Django with Authlib.
        And understand how OpenID Connect works.

OpenID Connect 1.0 are built custom grant types and grant extensions. You need to
read the Authorization Server chapter at first.

.. module:: authlib.oauth2.rfc6749.grants
    :noindex:

Looking for OpenID Connect Client? Head over to :ref:`django_client`.

Understand JWT
--------------

OpenID Connect 1.0 uses JWT a lot. Make sure you have the basic understanding
of :ref:`jose`.

For OpenID Connect, we need to understand at lease four concepts:

1. **alg**: Algorithm for JWT
2. **key**: Private key for JWT
3. **iss**: Issuer value for JWT
4. **exp**: JWT expires time

alg
~~~

The algorithm to sign a JWT. This is the ``alg`` value defined in header
part of a JWS:

.. code-block:: json

    {"alg": "RS256"}

The available algorithms are defined in :ref:`specs/rfc7518`, which are:

- HS256: HMAC using SHA-256
- HS384: HMAC using SHA-384
- HS512: HMAC using SHA-512
- RS256: RSASSA-PKCS1-v1_5 using SHA-256
- RS384: RSASSA-PKCS1-v1_5 using SHA-384
- RS512: RSASSA-PKCS1-v1_5 using SHA-512
- ES256: ECDSA using P-256 and SHA-256
- ES384: ECDSA using P-384 and SHA-384
- ES512: ECDSA using P-521 and SHA-512
- PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
- PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
- PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512

The HMAC using SHA algorithms are not suggested since you need to share
secrets between server and client. Most OpenID Connect services are using
``RS256``.

key
~~~

A private key is required to generate JWT. The key that you are going to use
dependents on the ``alg`` you are using. For instance, the alg is ``RS256``,
you need to use an RSA private key. It can be set with::

    key = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEog...'''

    # or in JWK format
    key = {"kty": "RSA", "n": ...}

iss
~~~

The ``iss`` value in JWT payload. The value can be your website name or URL.
For example, Google is using::

    {"iss": "https://accounts.google.com"}


Code Flow
---------

OpenID Connect authorization code flow relies on the OAuth2 authorization code
flow and extends it. In OpenID Connect, there will be a ``nonce`` parameter in
request, we need to save it into database for later use. In this case, we have
to rewrite our ``AuthorizationCode`` db model::

    class AuthorizationCode(Model, AuthorizationCodeMixin):
        user = ForeignKey(User, on_delete=CASCADE)
        client_id = CharField(max_length=48, db_index=True)
        code = CharField(max_length=120, unique=True, null=False)
        redirect_uri = TextField(default='', null=True)
        response_type = TextField(default='')
        scope = TextField(default='', null=True)
        auth_time = IntegerField(null=False, default=now_timestamp)

        # add nonce
        nonce = CharField(max_length=120, default='', null=True)

        # ... other fields and methods ...

OpenID Connect Code flow is the same as Authorization Code flow, but with
extended features. We can apply the :class:`OpenIDCode` extension to
``AuthorizationCodeGrant``.

First, we need to implement the missing methods for ``OpenIDCode``::

    from authlib.oidc.core import grants, UserInfo

    class OpenIDCode(grants.OpenIDCode):
        def exists_nonce(self, nonce, request):
            try:
                AuthorizationCode.objects.get(
                    client_id=request.payload.client_id, nonce=nonce
                )
                return True
            except AuthorizationCode.DoesNotExist:
                return False

        def get_jwt_config(self, grant):
            return {
                'key': read_private_key_file(key_path),
                'alg': 'RS512',
                'iss': 'https://example.com',
                'exp': 3600
            }

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.pk),
                name=user.name,
                email=user.email,
            ).filter(scope)

Second, since there is one more ``nonce`` value in ``AuthorizationCode`` data,
we need to save this value into database. In this case, we have to update our
``AuthorizationCodeGrant.save_authorization_code`` method::

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            # openid request MAY have "nonce" parameter
            nonce = request.payload.data.get('nonce')
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.payload.scope,
                user=request.user,
                nonce=nonce,
            )
            auth_code.save()
            return auth_code

Finally, you can register ``AuthorizationCodeGrant`` with ``OpenIDCode``
extension::

    # register it to grant endpoint
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode(require_nonce=True)])

The difference between OpenID Code flow and the standard code flow is that
OpenID Connect request has a scope of "openid":

.. code-block:: http

    GET /authorize?
    response_type=code
    &scope=openid%20profile%20email
    &client_id=s6BhdRkqt3
    &state=af0ifjsldkj
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb HTTP/1.1
    Host: server.example.com

With the example above, you will also have to change the scope of your client
in your application to something like ``openid profile email``.

Now that you added the ``openid`` scope to your application, an OpenID token
will be provided to this app whenever a client asks for a token with an
``openid`` scope.


Implicit Flow
-------------

The Implicit Flow is mainly used by Clients implemented in a browser using
a scripting language. You need to implement the missing methods of
:class:`OpenIDImplicitGrant` before register it::

    from authlib.oidc.core import grants

    class OpenIDImplicitGrant(grants.OpenIDImplicitGrant):
        def exists_nonce(self, nonce, request):
            try:
                AuthorizationCode.objects.get(
                    client_id=request.payload.client_id, nonce=nonce)
                )
                return True
            except AuthorizationCode.DoesNotExist:
                return False

        def get_jwt_config(self):
            return {
                'key': read_private_key_file(key_path),
                'alg': 'RS512',
                'iss': 'https://example.com',
                'exp': 3600
            }

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.pk),
                name=user.name,
                email=user.email,
            ).filter(scope)

    server.register_grant(OpenIDImplicitGrant)


Hybrid Flow
------------

Hybrid flow is a mix of the code flow and implicit flow. You only need to
implement the authorization endpoint part, token endpoint will be handled
by Authorization Code Flow.

OpenIDHybridGrant is a subclass of OpenIDImplicitGrant, so the missing methods
are the same, except that OpenIDHybridGrant has one more missing method, that
is ``save_authorization_code``. You can implement it like this::

    from authlib.oidc.core import grants

    class OpenIDHybridGrant(grants.OpenIDHybridGrant):
        def save_authorization_code(self, code, request):
            # openid request MAY have "nonce" parameter
            nonce = request.payload.data.get('nonce')
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.payload.scope,
                user=request.user,
                nonce=nonce,
            )
            auth_code.save()
            return auth_code

        def exists_nonce(self, nonce, request):
            try:
                AuthorizationCode.objects.get(
                    client_id=request.payload.client_id, nonce=nonce)
                )
                return True
            except AuthorizationCode.DoesNotExist:
                return False

        def get_jwt_config(self):
            return {
                'key': read_private_key_file(key_path),
                'alg': 'RS512',
                'iss': 'https://example.com',
                'exp': 3600
            }

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.pk),
                name=user.name,
                email=user.email,
            ).filter(scope)

    # register it to grant endpoint
    server.register_grant(OpenIDHybridGrant)


Since all OpenID Connect Flow requires ``exists_nonce``, ``get_jwt_config``
and ``generate_user_info`` methods, you can create shared functions for them.
