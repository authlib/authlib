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
you need to use an RSA private key. It can be set with:

.. code-block:: python

    key = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEog...'''

    # or in JWK format
    key = {"kty": "RSA", "n": ...}

iss
~~~

The ``iss`` value in JWT payload. The value can be your website name or URL.
For example, Google is using:

.. code-block:: json

    {"iss": "https://accounts.google.com"}

Code Flow
---------

OpenID Connect authorization code flow relies on the OAuth2 authorization code
flow and extends it. In OpenID Connect, there will be a ``nonce`` parameter in
request, we need to save it into database for later use. In this case, we have
to rewrite our ``AuthorizationCode`` db model with the OpenID Connect
:class:`~authlib.oidc.core.AuthorizationCodeMixin`:

.. code-block:: python

    from authlib.oidc.core import AuthorizationCodeMixin

    class AuthorizationCode(Model, AuthorizationCodeMixin):
        user = ForeignKey(User, on_delete=CASCADE)
        client_id = CharField(max_length=48, db_index=True)
        code = CharField(max_length=120, unique=True, null=False)
        redirect_uri = TextField(default='', null=True)
        response_type = TextField(default='')
        scope = TextField(default='', null=True)
        issued_at = IntegerField(null=False, default=now_timestamp)

        # add nonce and the authentication of the user
        nonce = CharField(max_length=120, default='', null=True)
        auth_time = IntegerField(null=True)
        acr = CharField(max_length=255, null=True)
        amr = CharField(max_length=255, null=True)

        def get_nonce(self):
            return self.nonce

        def get_auth_time(self):
            return self.auth_time

        def get_acr(self):
            return self.acr

        def get_amr(self):
            return self.amr.split() if self.amr else None

        # ... other fields and methods ...

OpenID Connect Code flow is the same as Authorization Code flow, but with
extended features. We can apply the :class:`OpenIDCode` extension to
``AuthorizationCodeGrant``.

First, we need to implement the missing methods for ``OpenIDCode``:

.. code-block:: python

    from joserfc.jwk import KeySet
    from authlib.oidc.core import grants, UserInfo

    class OpenIDCode(grants.OpenIDCode):
        def resolve_client_private_key(self, client):
            with open(jwks_file_path) as f:
                data = json.load(f)
            return KeySet.import_key_set(data)

        def get_client_claims(self, client):
            return {
                'iss': 'https://example.com',
            }

        def exists_nonce(self, nonce, request):
            try:
                AuthorizationCode.objects.get(
                    client_id=request.payload.client_id, nonce=nonce
                )
                return True
            except AuthorizationCode.DoesNotExist:
                return False

        def generate_user_info(self, user, scope, claims):
            return UserInfo(
                sub=str(user.pk),
                name=user.get_full_name(),
                email=user.email,
            ).filter(scope, claims)

Second, the ``AuthorizationCode`` data has more values: the ``nonce``
parameter, and the authentication of the user. ``OpenIDCode`` sets the time,
the ``acr`` and the ``amr`` of this authentication in ``request.auth_time``,
``request.acr`` and ``request.amr``, from the authorization session (see
:ref:`django_oidc_max_age`). They become the ``auth_time``, ``acr`` and ``amr`` claims of
the ID token. Save these values in the
``AuthorizationCodeGrant.save_authorization_code`` method:

.. code-block:: python

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            nonce = request.payload.data.get('nonce')
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.payload.redirect_uri,
                scope=request.scope,
                user=request.user,
                nonce=nonce,
                auth_time=request.auth_time,
                acr=request.acr,
                amr=" ".join(request.amr or []),
            )
            auth_code.save()
            return auth_code

Finally, you can register ``AuthorizationCodeGrant`` with ``OpenIDCode``
extension:

.. code-block:: python

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
:class:`OpenIDImplicitGrant` before register it.

Per OpenID Connect Core 1.0 §2, the authorization server should not process the
nonce, other than putting it in the ID token. The client checks it. This
example accepts every nonce:

.. code-block:: python

    from joserfc.jwk import KeySet
    from authlib.oidc.core import grants

    class OpenIDImplicitGrant(grants.OpenIDImplicitGrant):
        def resolve_client_private_key(self, client):
            with open(jwks_file_path) as f:
                data = json.load(f)
            return KeySet.import_key_set(data)

        def get_client_claims(self, client):
            return {
                'iss': 'https://example.com',
            }

        def exists_nonce(self, nonce, request):
            return False

        def generate_user_info(self, user, scope, claims):
            return UserInfo(
                sub=str(user.pk),
                name=user.get_full_name(),
                email=user.email,
            ).filter(scope, claims)

    server.register_grant(OpenIDImplicitGrant)

Hybrid Flow
------------

Hybrid flow is a mix of the code flow and implicit flow. You only need to
implement the authorization endpoint part, token endpoint will be handled
by Authorization Code Flow.

OpenIDHybridGrant is a subclass of OpenIDImplicitGrant, so the missing methods
are the same, except that OpenIDHybridGrant has one more missing method, that
is ``save_authorization_code``. You can implement it like this:

.. code-block:: python

    from joserfc.jwk import KeySet
    from authlib.oidc.core import grants

    class OpenIDHybridGrant(grants.OpenIDHybridGrant):
        def resolve_client_private_key(self, client):
            with open(jwks_file_path) as f:
                data = json.load(f)
            return KeySet.import_key_set(data)

        def get_client_claims(self, client):
            return {
                'iss': 'https://example.com',
            }

        def save_authorization_code(self, code, request):
            nonce = request.payload.data.get('nonce')
            client = request.client
            auth_code = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=request.payload.redirect_uri,
                scope=request.scope,
                user=request.user,
                nonce=nonce,
                auth_time=request.auth_time,
                acr=request.acr,
                amr=" ".join(request.amr or []),
            )
            auth_code.save()
            return auth_code

        def exists_nonce(self, nonce, request):
            try:
                AuthorizationCode.objects.get(
                    client_id=request.payload.client_id, nonce=nonce
                )
                return True
            except AuthorizationCode.DoesNotExist:
                return False

        def generate_user_info(self, user, scope, claims):
            return UserInfo(
                sub=str(user.pk),
                name=user.get_full_name(),
                email=user.email,
            ).filter(scope, claims)

    # register it to grant endpoint
    server.register_grant(OpenIDHybridGrant)

All OpenID Connect flows require ``exists_nonce``, ``resolve_client_private_key``,
``get_client_claims`` and ``generate_user_info`` methods. You can create shared
functions for ``resolve_client_private_key``, ``get_client_claims`` and
``generate_user_info``.

.. _django_oidc_claims_parameter:

Claims Parameter
----------------

A client can request individual claims with the ``claims`` parameter (OpenID
Connect Core 1.0 §5.5). Its ``id_token`` member lists claims for the ID token,
and its ``userinfo`` member lists claims for the UserInfo endpoint. Register
:class:`~authlib.oidc.core.ClaimsParameter` to support it, and publish
``"claims_parameter_supported": true`` in the server metadata:

.. code-block:: python

    from authlib.oidc.core import ClaimsParameter

    server.register_extension(ClaimsParameter())

The ``claims`` argument of ``generate_user_info`` contains the requested
claims. ``UserInfo.filter(scope, claims)`` returns them with the claims of the
scope. These claims can be outside the scope: show them on the consent page,
and only return the claims that the user accepts to share.

The parameter is in ``request.claims_request``. Save it with the authorization
code, and return it from ``get_claims_request``. With the hybrid flow, also
save it in ``OpenIDHybridGrant.save_authorization_code``:

.. skip: next "redefines the AuthorizationCode model"

.. code-block:: python

    from django.db.models import JSONField

    class AuthorizationCode(Model, AuthorizationCodeMixin):
        # ... the fields of the authorization code
        claims_request = JSONField(null=True)

        def get_claims_request(self):
            return self.claims_request

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            auth_code = AuthorizationCode(
                # ... the values of the code flow example
                claims_request=request.claims_request,
            )
            auth_code.save()
            return auth_code

For the UserInfo endpoint, save the parameter with the tokens too, in a
``claims_request`` field of the ``OAuth2Token`` model. A token issued with a
code gets the parameter of the code. A token issued by the refresh token grant
gets the parameter of the previous token:

.. code-block:: python

    def get_claims_request(request):
        if request.authorization_code:
            return request.authorization_code.get_claims_request()

        if request.refresh_token:
            return request.refresh_token.claims_request

        return getattr(request, "claims_request", None)

    from authlib.integrations.django_oauth2 import AuthorizationServer

    class MyAuthorizationServer(AuthorizationServer):
        def save_token(self, token, request):
            token = {**token, "claims_request": get_claims_request(request)}
            return super().save_token(token, request)

Then return it from
:meth:`~authlib.oidc.core.UserInfoEndpoint.get_token_claims_request`:

.. code-block:: python

    from authlib.oidc.core import UserInfoEndpoint

    class MyUserInfoEndpoint(UserInfoEndpoint):
        # ... the other methods of the endpoint

        def get_token_claims_request(self, token):
            return token.claims_request

.. _django_oidc_max_age:

Authorization Session
---------------------

A client can ask for a recent login with ``prompt=login`` or ``max_age``, or
for a new consent with ``prompt=consent``. Authlib applies these rules with an
:class:`~authlib.oauth2.AuthorizationSession`.
:ref:`authorization_session` explains the rules and the pitfalls.

Store the time of the login in the session:

.. code-block:: python

    import time
    from django.contrib.auth import login

    def login_view(request):
        ...
        login(request, user)
        request.session["auth_time"] = int(time.time())

Subclass the authorization session. It keeps the start time of the requests
in the Django session. Give the time of the interactions, and tell if the
user must give their consent:

.. code-block:: python

    from authlib.oauth2 import AuthorizationSession

    class MyAuthorizationSession(AuthorizationSession):
        def get_interaction_time(self, request, interaction):
            if interaction == "login":
                return self.session.get("auth_time")
            if interaction == "consent":
                consent = get_consent(self.user, request.client)
                return consent.issued_at.timestamp() if consent else None
            return None

        def is_consent_needed(self, request):
            consent = get_consent(self.user, request.client)
            return consent is None or not consent.covers(request.scope)

Pass it to ``get_consent_grant``. When the user must go through an
interaction, such as a login, it is in ``grant.interactions``, and
``grant.prompt`` is the first of them:

.. code-block:: python

    def authorize(request):
        user = request.user if request.user.is_authenticated else None
        authorization_session = MyAuthorizationSession(user, request.session)
        try:
            grant = server.get_consent_grant(request, session=authorization_session)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if request.method == "GET" and "login" in grant.interactions:
            return redirect_to_login(request.get_full_path())
        ...
