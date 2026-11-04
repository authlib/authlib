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
        issued_at = IntegerField(null=False, default=now_timestamp)

        # add nonce and auth_time
        nonce = CharField(max_length=120, default='', null=True)
        auth_time = IntegerField(null=True)

        def get_auth_time(self):
            return self.auth_time

        # ... other fields and methods ...

OpenID Connect Code flow is the same as Authorization Code flow, but with
extended features. We can apply the :class:`OpenIDCode` extension to
``AuthorizationCodeGrant``.

First, we need to implement the missing methods for ``OpenIDCode``::

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

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.pk),
                name=user.name,
                email=user.email,
            ).filter(scope)

Second, the ``AuthorizationCode`` data has two more values: the ``nonce``
parameter, and the time of the user authentication. ``OpenIDCode`` sets this
time in ``request.auth_time``, from the authorization session (see
:ref:`django_oidc_max_age`). It becomes the
``auth_time`` claim of the ID token. Save these values in the
``AuthorizationCodeGrant.save_authorization_code`` method::

    class AuthorizationCodeGrant(_AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            # openid request MAY have "nonce" parameter
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
            try:
                AuthorizationCode.objects.get(
                    client_id=request.payload.client_id, nonce=nonce)
                )
                return True
            except AuthorizationCode.DoesNotExist:
                return False

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
            # openid request MAY have "nonce" parameter
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

        def generate_user_info(self, user, scope):
            return UserInfo(
                sub=str(user.pk),
                name=user.name,
                email=user.email,
            ).filter(scope)

    # register it to grant endpoint
    server.register_grant(OpenIDHybridGrant)

Since all OpenID Connect Flow require ``exists_nonce``, ``resolve_client_private_key``,
``get_client_claims``, ``get_client_algorithm`` and ``generate_user_info``
methods, you can create shared functions for them.

.. _django_oidc_max_age:

Authorization Session
---------------------

A client can ask for a recent authentication of the user, with
``prompt=login``, with the ``max_age`` parameter or with the
``default_max_age`` client metadata. It can also ask for a new consent with
``prompt=consent``, or for an account selection with
``prompt=select_account``. To apply these parameters, Authlib needs facts
about the session of the user. Give them with an
:class:`~authlib.oidc.core.AuthorizationSessionMixin`.

Store the time of the login in the session::

    import time
    from django.contrib.auth import login

    def login_view(request):
        ...
        login(request, user)
        request.session["auth_time"] = int(time.time())

Then implement the authorization session::

    import time
    from authlib.oidc.core import AuthorizationSessionMixin

    class AuthorizationSession(AuthorizationSessionMixin):
        def __init__(self, request):
            self.session = request.session
            self.user = request.user if request.user.is_authenticated else None

        def get_user(self):
            return self.user

        def get_request_time(self, request):
            now = int(time.time())
            stored = self.session.get("request_times", {})
            times = {
                key: start for key, start in stored.items() if now - start <= 600
            }
            times.setdefault(request.authorization_key, now)
            if times != stored:
                self.session["request_times"] = times

            return times[request.authorization_key]

        def end_request(self, request):
            times = self.session.get("request_times", {})
            times.pop(request.authorization_key, None)
            self.session["request_times"] = times

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
``grant.prompt`` is the first of them::

    def authorize(request):
        authorization_session = AuthorizationSession(request)
        try:
            grant = server.get_consent_grant(request, session=authorization_session)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if request.method == "GET" and grant.prompt == "login":
            return redirect_to_login(request.get_full_path())
        ...

The interactions come in this order: ``"login"``, ``"select_account"`` and
``"consent"``. A login after the start of the request also counts as an
account selection, so an anonymous user only has to log in. With
``prompt=none``, the server returns an error instead, such as
``login_required`` or ``consent_required``.

The time of the login must come from a real authentication, with a password
or another factor. Do not update it when the user switches to another account
or resumes a session. It becomes the ``auth_time`` claim of the ID token.

An interaction that the client asks for is done when it happened after the
authorization request started: a login after this time satisfies
``prompt=login`` and ``max_age=0``, and a consent after this time satisfies
``prompt=consent``. ``max_age`` is measured from this time. Without
``get_request_time``, these interactions are asked again and again, and the
age of the authentication is measured each time you call
``get_consent_grant``.

Authlib calls ``get_request_time`` from the first visit, when the user must
go through an interaction, and when a rule needs the start time. It does not
call it with ``prompt=none``.
``request.authorization_key`` is a hash of the authorization request
parameters. It is the same before and after the login, and when the user
submits the consent form. Two authorization requests with the same parameters
have the same key. Clients that send a unique ``state``, ``nonce`` or
``code_challenge`` avoid this.

Keep the time on the server side, for instance in the session. Do not read it
from a request parameter or a form field. A user could send an old time and
skip the login. Authlib calls ``end_request`` when the request ends: when the
user accepts or denies it, and when ``get_consent_grant`` raises an error.
Otherwise, the same authorization request sent again later would reuse the
old time, and the user would not have to log in. The example also drops the
times older than 10 minutes. They come from requests that never end, for
instance when the user leaves the login page. This keeps the session small.

The time must still be in the session when the user comes back from the login:

- If your login view clears or replaces the session, copy ``request_times``
  into the new session.
- A cross-site ``POST`` to the authorization endpoint comes without the
  session cookie when it is ``SameSite=Lax``. Redirect such requests to a
  ``GET`` with the same parameters first, or keep the times in a server-side
  cache.

``is_consent_needed`` tells if the user must give their consent, according to
the consents you store: there is none, it was revoked, or it does not cover
the requested scope. A client can still ask for a consent with
``prompt=consent``. ``is_account_selection_needed`` works the same way for the
account selection.

Without an authorization session, ``max_age`` is ignored, except
``max_age=0``, and the ``auth_time`` claim is the current time. This is
deprecated.

The :ref:`specs/rfc9470` extension applies ``max_age`` to the requests without
the ``openid`` scope too.
