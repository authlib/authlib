import time
from types import SimpleNamespace

import pytest
from flask import json
from joserfc import jwt
from joserfc.jwk import KeySet

import authlib.oidc.core as oidc_core
from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from tests.util import read_file_path

from ..models import User
from ..models import db

issuer = "https://provider.test/"
userinfo_url = "https://provider.test/oauth/userinfo"


@pytest.fixture
def jwks():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


@pytest.fixture(autouse=True)
def server(server, app, jwks):
    class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
        def get_jwks(self):
            return jwks

    class UserInfoEndpoint(oidc_core.UserInfoEndpoint):
        def get_issuer(self):
            return issuer

        def get_token_client(self, token):
            return self.server.query_client(token["client_id"])

        def get_token_user(self, token):
            return db.session.get(User, int(token["sub"]))

        def generate_user_info(self, user, scope, claims):
            return user.generate_user_info().filter(scope, claims)

        def resolve_private_key(self):
            return jwks

    resource_protector = ResourceProtector()
    resource_protector.register_token_validator(
        MyJWTBearerTokenValidator(issuer=issuer, resource_server=userinfo_url)
    )
    server.register_endpoint(UserInfoEndpoint(resource_protector=resource_protector))

    @app.route("/oauth/userinfo", methods=["GET", "POST"])
    def userinfo():
        return server.create_endpoint_response("userinfo")

    return server


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "openid profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def create_access_token(jwks, client, user, scope, aud=userinfo_url):
    now = int(time.time())
    claims = {
        "iss": issuer,
        "exp": now + 3600,
        "aud": aud,
        "sub": str(user.get_user_id()),
        "client_id": client.client_id,
        "iat": now,
        "jti": generate_token(16),
        "scope": scope,
    }
    return jwt.encode({"alg": "RS256", "typ": "at+jwt"}, claims, key=jwks)


def test_jwt_access_token(test_client, jwks, client, user):
    """The userinfo endpoint accepts RFC 9068 JWT access tokens."""
    access_token = create_access_token(jwks, client, user, "openid profile")
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.status_code == 200

    resp = json.loads(rv.data)
    assert resp["sub"] == str(user.id)
    assert resp["name"] == "foo"
    assert "email" not in resp


def test_jwt_access_token_signed_response(test_client, db, jwks, client, user):
    """The signed userinfo response uses the client of the JWT access token."""
    client.set_client_metadata(
        {
            "scope": "openid profile",
            "redirect_uris": ["https://client.test/authorized"],
            "userinfo_signed_response_alg": "RS256",
        }
    )
    db.session.add(client)
    db.session.commit()

    access_token = create_access_token(jwks, client, user, "openid profile")
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.headers["Content-Type"] == "application/jwt"

    token = jwt.decode(rv.data, jwks)
    assert token.claims["sub"] == str(user.id)
    assert token.claims["iss"] == issuer
    assert token.claims["aud"] == client.client_id


def test_jwt_access_token_without_openid_scope(test_client, jwks, client, user):
    """A JWT access token without the openid scope is rejected."""
    access_token = create_access_token(jwks, client, user, "profile")
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.status_code == 403
    assert json.loads(rv.data)["error"] == "insufficient_scope"


def test_jwt_access_token_several_audiences(test_client, jwks, client, user):
    """A JWT access token is accepted if its audience contains the userinfo URL."""
    access_token = create_access_token(
        jwks, client, user, "openid", aud=["https://api.test", userinfo_url]
    )
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.status_code == 200


def test_jwt_access_token_other_audience(test_client, jwks, client, user):
    """A JWT access token issued for another resource server is rejected."""
    access_token = create_access_token(
        jwks, client, user, "openid", aud="https://api.test"
    )
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_token"


def test_jwt_access_token_unknown_user(test_client, jwks, client):
    """A JWT access token for a user that does not exist anymore is rejected."""
    access_token = create_access_token(jwks, client, User(id=999), "openid")
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_token"


def test_jwt_access_token_unknown_client(test_client, jwks, user):
    """A JWT access token for a client that does not exist anymore is rejected."""
    client = SimpleNamespace(client_id="unknown-client")
    access_token = create_access_token(jwks, client, user, "openid")
    headers = {"Authorization": f"Bearer {access_token}"}
    rv = test_client.get("/oauth/userinfo", headers=headers)
    assert rv.status_code == 401
    assert json.loads(rv.data)["error"] == "invalid_token"
