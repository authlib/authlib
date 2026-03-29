import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc9068 import JWTBearerTokenGenerator
from tests.util import read_file_path

from ..models import CodeGrantMixin
from ..models import User
from ..models import save_authorization_code

issuer = "https://authlib.test/"


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
    return read_file_path("jwks_private.json")


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def token_generator(server, jwks):
    class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
        def get_jwks(self):
            return jwks

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
    claims = jwt.decode(access_token, jwks)

    assert claims["iss"] == issuer
    assert claims["sub"] == user.id
    assert claims["scope"] == client.scope
    assert claims["client_id"] == client.client_id

    # This specification registers the 'application/at+jwt' media type, which can
    # be used to indicate that the content is a JWT access token. JWT access tokens
    # MUST include this media type in the 'typ' header parameter to explicitly
    # declare that the JWT represents an access token complying with this profile.
    # Per the definition of 'typ' in Section 4.1.9 of [RFC7515], it is RECOMMENDED
    # that the 'application/' prefix be omitted. Therefore, the 'typ' value used
    # SHOULD be 'at+jwt'.

    assert claims.header["typ"] == "at+jwt"


def test_generate_jwt_access_token_extra_claims(
    test_client, token_generator, user, client, jwks
):
    """Authorization servers MAY return arbitrary attributes not defined in any
    existing specification, as long as the corresponding claim names are collision
    resistant or the access tokens are meant to be used only within a private
    subsystem. Please refer to Sections 4.2 and 4.3 of [RFC7519] for details.
    """

    def get_extra_claims(client, grant_type, user, scope):
        return {"username": user.username}

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
    claims = jwt.decode(access_token, jwks)
    assert claims["username"] == user.username


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
    claims = jwt.decode(access_token, jwks)

    assert claims["sub"] == client.client_id


def test_optional_fields(test_client, token_generator, user, client, jwks):
    token_generator.get_auth_time = lambda *args: 1234
    token_generator.get_amr = lambda *args: "amr"
    token_generator.get_acr = lambda *args: "acr"

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
    claims = jwt.decode(access_token, jwks)

    assert claims["auth_time"] == 1234
    assert claims["amr"] == "amr"
    assert claims["acr"] == "acr"
