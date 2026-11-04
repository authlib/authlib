.. _flask_oidc_server:

Flask OIDC Provider
===================

.. meta::
    :description: How to create an OpenID Connect 1.0 server in Flask with Authlib.
        And understand how OpenID Connect works.

OpenID Connect 1.0 is supported since version 0.6. The integrations are built
with :ref:`flask_oauth2_custom_grant_types` and :ref:`flask_oauth2_grant_extensions`.
Since OpenID Connect is built on OAuth 2.0 frameworks, you need to read
:ref:`flask_oauth2_server` at first.

.. module:: authlib.oauth2.rfc6749.grants
    :noindex:

Looking for OpenID Connect Client? Head over to :ref:`flask_client`.

Understand JWT
--------------

OpenID Connect 1.0 uses JWT a lot. Make sure you have the basic understanding
of :ref:`jose`.

For OpenID Connect, we need to understand at least four concepts:

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

A private key is required to generate a JWT. The key that you are going to use
dependents on the ``alg`` you are using. For instance, the alg is ``RS256``,
you need to use an RSA private key. It can be set with::

    key = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEog...'''

    # or in JWK format
    key = {"kty": "RSA", "n": ...}

iss
~~~

The ``iss`` value in the JWT payload. The value can be your website name or
URL. For example, Google is using::

    {"iss": "https://accounts.google.com"}

.. _flask_odic_code:

Code Flow
---------

OpenID Connect authorization code flow relies on the OAuth2 authorization code
flow and extends it.

OpenID Connect Code flow is the same as Authorization Code flow, but with
extended features. We can apply the :class:`OpenIDCode` extension to
:ref:`flask_oauth2_code_grant`.

First, we need to implement the missing methods for ``OpenIDCode``::

    from flask import session
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
            exists = AuthorizationCode.query.filter_by(
                client_id=request.payload.client_id, nonce=nonce
            ).first()
            return bool(exists)

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=user.id,
                name=user.name,
                email=user.email,
            ).filter(scope)

        def get_auth_time(self, request):
            return session.get("auth_time")

Second, since there is one more ``nonce`` value in the ``AuthorizationCode``
data, we need to save this value into the database. In this case, we have to
update our :ref:`flask_oauth2_code_grant` ``save_authorization_code`` method::

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            # openid request MAY have "nonce" parameter
            nonce = request.payload.data.get('nonce')
            auth_code = AuthorizationCode(
                code=code,
                client_id=request.client.client_id,
                redirect_uri=request.payload.redirect_uri,
                scope=request.scope,
                user_id=request.user.id,
                nonce=nonce,
            )
            db.session.add(auth_code)
            db.session.commit()
            return auth_code

        # ...

Finally, you can register ``AuthorizationCodeGrant`` with the ``OpenIDCode``
extension::

    # register it to grant endpoint
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode(require_nonce=True)])

The difference between OpenID Code flow and the standard code flow is that
OpenID Connect requests have a scope of "openid":

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

.. _flask_odic_implicit:

Implicit Flow
-------------

The Implicit Flow is mainly used by Clients implemented in a browser using
a scripting language. You need to implement the missing methods of
:class:`OpenIDImplicitGrant` before registering it::

    from flask import session
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
            exists = AuthorizationCode.query.filter_by(
                client_id=request.payload.client_id, nonce=nonce
            ).first()
            return bool(exists)

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=user.id,
                name=user.name,
                email=user.email,
            ).filter(scope)

        def get_auth_time(self, request):
            return session.get("auth_time")

    server.register_grant(OpenIDImplicitGrant)

.. _flask_odic_hybrid:

Hybrid Flow
------------

The Hybrid flow is a mix of code flow and implicit flow. You only need to
implement the authorization endpoint part, as token endpoint will be handled
by Authorization Code Flow.

OpenIDHybridGrant is a subclass of OpenIDImplicitGrant, so the missing methods
are the same, except that OpenIDHybridGrant has one more missing method, that
is ``save_authorization_code``. You can implement it like this::

    from flask import session
    from joserfc.jwk import KeySet
    from authlib.oidc.core import grants
    from authlib.common.security import generate_token

    class OpenIDHybridGrant(grants.OpenIDHybridGrant):
        def resolve_client_private_key(self, client):
            with open(jwks_file_path) as f:
                data = json.load(f)
            return KeySet.import_key_set(data)

        def get_client_claims(self, client):
            return {
                'iss': 'https://example.com',
            }

        def get_client_algorithm(self, client):
            return 'RS512'

        def save_authorization_code(self, code, request):
            nonce = request.payload.data.get('nonce')
            item = AuthorizationCode(
                code=code,
                client_id=request.client.client_id,
                redirect_uri=request.payload.redirect_uri,
                scope=request.scope,
                user_id=request.user.id,
                nonce=nonce,
            )
            db.session.add(item)
            db.session.commit()
            return code

        def exists_nonce(self, nonce, request):
            exists = AuthorizationCode.query.filter_by(
                client_id=request.payload.client_id, nonce=nonce
            ).first()
            return bool(exists)

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=user.id,
                name=user.name,
                email=user.email,
            ).filter(scope)

        def get_auth_time(self, request):
            return session.get("auth_time")

    # register it to grant endpoint
    server.register_grant(OpenIDHybridGrant)

Since all OpenID Connect Flow require ``exists_nonce``, ``resolve_client_private_key``,
``get_client_claims``, ``get_client_algorithm``, ``generate_user_info`` and
``get_auth_time`` methods, you can create shared functions for them.

.. _flask_odic_max_age:

Authentication Age
------------------

A client can ask for a recent authentication of the user, with the
``max_age`` parameter or the ``default_max_age`` client metadata. It is a
number of seconds. When the last authentication of the user is older, the
user must log in again.

Store the time of the login in the session::

    import time
    from flask import session

    def login(user):
        session["user_id"] = user.id
        session["auth_time"] = int(time.time())

Then return it in ``get_auth_time``, as in the examples above. When the user
must log in, ``grant.prompt`` is ``"login"``::

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        try:
            grant = server.get_consent_grant(end_user=current_user())
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if grant.prompt == "login":
            return redirect(url_for("login", next=request.url))
        ...

With ``prompt=none``, the server returns a ``login_required`` error instead.
``max_age=0`` works like ``prompt=login``: ``grant.prompt`` stays ``"login"``
for this request, even after the login.

Find the `example of OpenID Connect server <https://github.com/authlib/example-oidc-server>`_.
