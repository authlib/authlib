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
you need to use an RSA private key. It can be set with:

.. code-block:: python

    key = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEog...'''

    # or in JWK format
    key = {"kty": "RSA", "n": ...}

iss
~~~

The ``iss`` value in the JWT payload. The value can be your website name or
URL. For example, Google is using:

.. code-block:: python

    {"iss": "https://accounts.google.com"}

.. _flask_odic_code:

Code Flow
---------

OpenID Connect authorization code flow relies on the OAuth2 authorization code
flow and extends it.

OpenID Connect Code flow is the same as Authorization Code flow, but with
extended features. We can apply the :class:`OpenIDCode` extension to
:ref:`flask_oauth2_code_grant`.

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
            exists = AuthorizationCode.query.filter_by(
                client_id=request.payload.client_id, nonce=nonce
            ).first()
            return bool(exists)

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.id),
                name=user.name,
                email=user.email,
            ).filter(scope)

Second, the ``AuthorizationCode`` data has two more values: the ``nonce``
parameter, and the time of the user authentication. ``OpenIDCode`` sets this
time in ``request.auth_time``, from the authorization session (see
:ref:`flask_odic_max_age`). It becomes the
``auth_time`` claim of the ID token. Save these values in the
:ref:`flask_oauth2_code_grant` ``save_authorization_code`` method:

.. code-block:: python

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            nonce = request.payload.data.get('nonce')
            auth_code = AuthorizationCode(
                code=code,
                client_id=request.client.client_id,
                redirect_uri=request.payload.redirect_uri,
                scope=request.scope,
                user_id=request.user.id,
                nonce=nonce,
                auth_time=request.auth_time,
            )
            db.session.add(auth_code)
            db.session.commit()
            return auth_code

        # ...

Finally, you can register ``AuthorizationCodeGrant`` with the ``OpenIDCode``
extension:

.. code-block:: python

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
:class:`OpenIDImplicitGrant` before registering it.

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

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.id),
                name=user.name,
                email=user.email,
            ).filter(scope)

    server.register_grant(OpenIDImplicitGrant)

.. _flask_odic_hybrid:

Hybrid Flow
------------

The Hybrid flow is a mix of code flow and implicit flow. You only need to
implement the authorization endpoint part, as token endpoint will be handled
by Authorization Code Flow.

OpenIDHybridGrant is a subclass of OpenIDImplicitGrant, so the missing methods
are the same, except that OpenIDHybridGrant has one more missing method, that
is ``save_authorization_code``. You can implement it like this:

.. code-block:: python

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
                auth_time=request.auth_time,
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
                sub=str(user.id),
                name=user.name,
                email=user.email,
            ).filter(scope)

    # register it to grant endpoint
    server.register_grant(OpenIDHybridGrant)

All OpenID Connect flows require ``exists_nonce``, ``resolve_client_private_key``,
``get_client_claims`` and ``generate_user_info`` methods. You can create shared
functions for ``resolve_client_private_key``, ``get_client_claims`` and
``generate_user_info``.

.. _flask_odic_max_age:

Authorization Session
---------------------

A client can ask for a recent login with ``prompt=login`` or ``max_age``, or
for a new consent with ``prompt=consent``. Authlib applies these rules with an
:class:`~authlib.oauth2.AuthorizationSession`.
:ref:`authorization_session` explains the rules and the pitfalls.

Store the time of the login in the session:

.. code-block:: python

    import time
    from flask import session

    def login(user):
        session["user_id"] = user.id
        session["auth_time"] = int(time.time())

Subclass the authorization session. It keeps the start time of the requests
in the Flask session. Give the time of the interactions, and tell if the user
must give their consent:

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

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        authorization_session = MyAuthorizationSession(current_user(), session)
        try:
            grant = server.get_consent_grant(session=authorization_session)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if request.method == "GET" and "login" in grant.interactions:
            return redirect(url_for("login", next=request.url))
        ...

Find the `example of OpenID Connect server <https://github.com/authlib/example-oidc-server>`_.

.. invisible-code-block: python

    from urllib.parse import parse_qs, urlparse

    from joserfc import jwt

    db.create_all()
    user = User(username="alice", name="Alice", email="alice@example.com")
    db.session.add(user)
    db.session.commit()
    client = Client(user_id=user.id, client_id="client-id", client_secret="client-secret")
    client.set_client_metadata({
        "redirect_uris": ["https://client.example/cb"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid profile",
    })
    db.session.add(client)
    db.session.commit()
    http = app.test_client()

    response = http.post("/test/authorize", query_string={
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "https://client.example/cb",
        "scope": "openid profile",
        "nonce": "n-0S6_WzA2Mj",
    })
    assert response.status_code == 303, response.data
    code = parse_qs(urlparse(response.location).query)["code"][0]

    response = http.post("/test/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://client.example/cb",
    }, auth=("client-id", "client-secret"))
    assert response.status_code == 200, response.json

    claims = jwt.decode(response.json["id_token"], public_jwks).claims
    assert claims["nonce"] == "n-0S6_WzA2Mj"
    assert claims["aud"] == ["client-id"]
    assert claims["sub"] == str(user.id)
    assert claims["name"] == "Alice"
