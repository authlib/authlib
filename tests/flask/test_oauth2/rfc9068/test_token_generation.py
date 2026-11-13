import warnings
from types import SimpleNamespace

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from tests.util import read_file_path

from ..models import CodeGrantMixin
from ..models import User
from ..models import save_authorization_code

issuer = "https://authlib.test/"
resource = "https://resource.test/"


@pytest.fixture
def user(db):
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)


@pytest.fixture
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture
def jwks():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def token_generator(server, jwks):
    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return resource

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    server.register_token_generator("default", token_generator)
    return token_generator


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


def test_generate_jwt_access_token(test_client, client, user, jwks):
    res = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": client.response_types[0],
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uris[0],
            "scope": client.scope,
            "user_id": user.id,
        },
    )

    params = dict(url_decode(urlparse.urlparse(res.location).query))
    code = params["code"]
    res = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "scope": " ".join(client.scope),
            "redirect_uri": client.redirect_uris[0],
        },
    )

    access_token = res.json["access_token"]
    token = jwt.decode(access_token, jwks)
    claims = token.claims

    assert claims["iss"] == issuer
    assert claims["sub"] == str(user.id)
    assert claims["scope"] == client.scope
    assert claims["client_id"] == client.client_id
    assert claims["aud"] == resource

    # This specification registers the 'application/at+jwt' media type, which can
    # be used to indicate that the content is a JWT access token. JWT access tokens
    # MUST include this media type in the 'typ' header parameter to explicitly
    # declare that the JWT represents an access token complying with this profile.
    # Per the definition of 'typ' in Section 4.1.9 of [RFC7515], it is RECOMMENDED
    # that the 'application/' prefix be omitted. Therefore, the 'typ' value used
    # SHOULD be 'at+jwt'.

    assert token.header["typ"] == "at+jwt"


def test_generate_jwt_access_token_extra_claims(
    test_client, token_generator, user, client, jwks
):
    """Authorization servers MAY return arbitrary attributes not defined in any
    existing specification, as long as the corresponding claim names are collision
    resistant or the access tokens are meant to be used only within a private
    subsystem. Please refer to Sections 4.2 and 4.3 of [RFC7519] for details.
    """

    def get_extra_claims(client, grant_type, user, scope, request):
        return {"username": user.username, "grant": request.payload.grant_type}

    token_generator.get_extra_claims = get_extra_claims

    res = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": client.response_types[0],
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uris[0],
            "scope": client.scope,
            "user_id": user.id,
        },
    )

    params = dict(url_decode(urlparse.urlparse(res.location).query))
    code = params["code"]
    res = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "scope": " ".join(client.scope),
            "redirect_uri": client.redirect_uris[0],
        },
    )

    access_token = res.json["access_token"]
    claims = jwt.decode(access_token, jwks).claims
    assert claims["username"] == user.username
    assert claims["grant"] == "authorization_code"


@pytest.mark.skip
def test_generate_jwt_access_token_no_user(test_client, client, user, jwks):
    res = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": client.response_types[0],
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uris[0],
            "scope": client.scope,
            #'user_id': user.id,
        },
    )

    params = dict(url_decode(urlparse.urlparse(res.location).query))
    code = params["code"]
    res = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "scope": " ".join(client.scope),
            "redirect_uri": client.redirect_uris[0],
        },
    )

    access_token = res.json["access_token"]
    claims = jwt.decode(access_token, jwks).claims

    assert claims["sub"] == client.client_id


def fetch_access_token(test_client, client, user):
    """Run the authorization code flow and return the access token."""
    res = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": client.response_types[0],
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uris[0],
            "scope": client.scope,
            "user_id": user.id,
        },
    )
    params = dict(url_decode(urlparse.urlparse(res.location).query))
    res = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "scope": " ".join(client.scope),
            "redirect_uri": client.redirect_uris[0],
        },
    )
    return res.json["access_token"]


def test_authentication_hooks_receive_request(test_client, server, user, client, jwks):
    """The auth_time, acr and amr hooks read the authentication of the token
    from the request."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return resource

        def get_auth_time(self, request):
            return request.authorization_code.issued_at

        def get_acr(self, request):
            return request.authorization_code.get_acr()

        def get_amr(self, request):
            return request.authorization_code.get_amr()

    server.register_token_generator("default", MyJWTBearerTokenGenerator(issuer=issuer))
    with warnings.catch_warnings():
        warnings.simplefilter("error", AuthlibDeprecationWarning)
        access_token = fetch_access_token(test_client, client, user)

    claims = jwt.decode(access_token, jwks).claims
    assert isinstance(claims["auth_time"], int)
    assert claims["acr"] == "urn:mace:incommon:iap:silver"
    assert claims["amr"] == ["pwd", "otp"]


def test_authentication_hooks_with_user(test_client, server, user, client, jwks):
    """Hooks whose first parameter is not 'request' get the user. They are
    deprecated but still work, also when they are set on the instance."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return resource

        def get_auth_time(self, user):
            return 1234

        def get_acr(self, user, request=None):
            return f"acr-{user.id}"

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    token_generator.get_amr = lambda user: ["pwd"]
    server.register_token_generator("default", token_generator)
    with pytest.warns(AuthlibDeprecationWarning, match="receives the user") as record:
        access_token = fetch_access_token(test_client, client, user)
        fetch_access_token(test_client, client, user)

    assert len(record) == 3
    claims = jwt.decode(access_token, jwks).claims

    assert claims["auth_time"] == 1234
    assert claims["acr"] == f"acr-{user.id}"
    assert claims["amr"] == ["pwd"]


def test_authentication_hooks_signatures(client, user, jwks):
    """A keyword-only request is given by keyword. A hook without a readable
    signature gets the user, with a warning."""

    class NoSignature:
        """Callable whose signature cannot be read."""

        __signature__ = "invalid"

        def __call__(self, user):
            return ["pwd"]

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return resource

        def get_acr(self, *, request):
            return request.acr

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    token_generator.get_amr = NoSignature()
    with pytest.warns(AuthlibDeprecationWarning, match="get_amr"):
        access_token = token_generator.access_token_generator(
            client,
            "authorization_code",
            user,
            "profile",
            request=SimpleNamespace(acr="silver"),
        )

    claims = jwt.decode(access_token, jwks).claims
    assert claims["acr"] == "silver"
    assert claims["amr"] == ["pwd"]


def test_hooks_without_request(client, user, jwks):
    """get_extra_claims, get_audiences and get_jti without a request parameter
    are deprecated but still work."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_extra_claims(self, client, grant_type, user, scope):
            return {"extra": "value"}

        def get_audiences(self, client, user, scope):
            return resource

        def get_jti(self, client, grant_type, user, scope):
            return "jti"

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    with pytest.warns(AuthlibDeprecationWarning, match="'request'") as record:
        for _ in range(2):
            access_token = token_generator.access_token_generator(
                client, "authorization_code", user, "profile"
            )

    assert len(record) == 3
    claims = jwt.decode(access_token, jwks).claims
    assert claims["extra"] == "value"
    assert claims["aud"] == resource
    assert claims["jti"] == "jti"


def test_jwks_dict(client, user, jwks):
    """A JWKS dict is still accepted by 'get_jwks' but deprecated."""

    class DictJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return read_file_path("jwks_private.json")

        def get_audiences(self, client, user, scope, request):
            return resource

    token_generator = DictJWTBearerTokenGenerator(issuer=issuer)
    with pytest.warns(AuthlibDeprecationWarning, match="KeySet.import_key_set"):
        access_token = token_generator.access_token_generator(
            client, "authorization_code", user, "profile"
        )
    claims = jwt.decode(access_token, jwks).claims
    assert claims["sub"] == str(user.id)


def test_non_recommended_algorithm(client, user, jwks):
    """The access token is signed with the configured 'alg', even when
    joserfc does not recommend it."""

    class RS512JWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope):
            return resource

    token_generator = RS512JWTBearerTokenGenerator(issuer=issuer, alg="RS512")
    access_token = token_generator.access_token_generator(
        client, "authorization_code", user, "profile"
    )
    token = jwt.decode(access_token, jwks, algorithms=["RS512"])
    assert token.header["alg"] == "RS512"


def test_default_audiences(client, user, jwks):
    """Without a get_audiences override, the client ID is used, with a warning."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    with pytest.warns(AuthlibDeprecationWarning, match="get_audiences") as record:
        for _ in range(2):
            access_token = token_generator.access_token_generator(
                client, "authorization_code", user, "profile"
            )

    assert len(record) == 1
    assert jwt.decode(access_token, jwks).claims["aud"] == client.client_id


def test_default_audiences_with_super(client, user, jwks):
    """An override that calls the default get_audiences gets the warning."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return [super().get_audiences(client, user, scope, request), resource]

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer)
    with pytest.warns(AuthlibDeprecationWarning, match="get_audiences"):
        token_generator.access_token_generator(
            client, "authorization_code", user, "profile"
        )


def test_get_audiences_override(client, user, jwks, token_generator):
    """Overriding get_audiences does not emit a warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", AuthlibDeprecationWarning)
        access_token = token_generator.access_token_generator(
            client, "authorization_code", user, "profile"
        )

    assert jwt.decode(access_token, jwks).claims["aud"] == resource


def test_explicit_expires_in(client, user, jwks, token_generator):
    """The JWT lifetime matches an expires_in given to the generator."""
    token = token_generator.generate(
        "authorization_code", client, user, "profile", expires_in=300
    )

    claims = jwt.decode(token["access_token"], jwks).claims
    assert token["expires_in"] == 300
    assert claims["exp"] - claims["iat"] == 300


def test_expires_generator(client, user, jwks):
    """The JWT lifetime matches the lifetime given by expires_generator."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return resource

    token_generator = MyJWTBearerTokenGenerator(issuer=issuer, expires_generator=600)
    token = token_generator.generate("authorization_code", client, user, "profile")

    claims = jwt.decode(token["access_token"], jwks).claims
    assert token["expires_in"] == 600
    assert claims["exp"] - claims["iat"] == 600


def test_override_without_expires_in(client, user, jwks):
    """An override without expires_in is deprecated but still works."""

    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

        def get_audiences(self, client, user, scope, request):
            return resource

        def access_token_generator(self, client, grant_type, user, scope):
            return super().access_token_generator(client, grant_type, user, scope)

    with pytest.warns(AuthlibDeprecationWarning, match="expires_in"):
        token_generator = MyJWTBearerTokenGenerator(issuer=issuer)

    token = token_generator.generate("authorization_code", client, user, "profile")
    assert jwt.decode(token["access_token"], jwks).claims["sub"] == str(user.id)
