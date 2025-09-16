import time

import pytest
from flask import json

from authlib.common.security import generate_token
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oauth2.rfc9068 import JWTIntrospectionEndpoint
from tests.util import read_file_path

from ..models import CodeGrantMixin
from ..models import User
from ..models import db
from ..models import save_authorization_code
from ..oauth2_server import create_basic_header

issuer = "https://provider.test/"
resource_server = "resource-server-id"


@pytest.fixture
def jwks():
    return read_file_path("jwks_private.json")


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def introspection_endpoint(server, app, jwks):
    class MyJWTIntrospectionEndpoint(JWTIntrospectionEndpoint):
        def get_jwks(self):
            return jwks

        def check_permission(self, token, client, request):
            return client.client_id == "client-id"

    endpoint = MyJWTIntrospectionEndpoint(issuer=issuer)
    server.register_endpoint(endpoint)

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response(MyJWTIntrospectionEndpoint.ENDPOINT_NAME)

    return endpoint


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


def create_access_token_claims(client, user):
    now = int(time.time())
    expires_in = now + 3600
    auth_time = now - 60

    return {
        "iss": issuer,
        "exp": expires_in,
        "aud": [resource_server],
        "sub": user.get_user_id(),
        "client_id": client.client_id,
        "iat": now,
        "jti": generate_token(16),
        "auth_time": auth_time,
        "scope": client.scope,
        "groups": ["admins"],
        "roles": ["student"],
        "entitlements": ["captain"],
    }


@pytest.fixture
def claims(client, user):
    return create_access_token_claims(client, user)


def create_access_token(claims, jwks, alg="RS256", typ="at+jwt"):
    header = {"alg": alg, "typ": typ}
    access_token = jwt.encode(
        header,
        claims,
        key=jwks,
        check=False,
    )
    return access_token.decode()


@pytest.fixture
def access_token(claims, jwks):
    return create_access_token(claims, jwks)


def test_introspection(test_client, client, user, access_token):
    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect", data={"token": access_token}, headers=headers
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"]
    assert resp["client_id"] == client.client_id
    assert resp["token_type"] == "Bearer"
    assert resp["scope"] == client.scope
    assert resp["sub"] == user.id
    assert resp["aud"] == [resource_server]
    assert resp["iss"] == issuer


def test_introspection_username(
    test_client, client, user, introspection_endpoint, access_token
):
    introspection_endpoint.get_username = lambda user_id: db.session.get(
        User, user_id
    ).username

    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect", data={"token": access_token}, headers=headers
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"]
    assert resp["username"] == user.username


def test_non_access_token_skipped(test_client, client, server):
    class MyIntrospectionEndpoint(IntrospectionEndpoint):
        def query_token(self, token, token_type_hint):
            return None

    server.register_endpoint(MyIntrospectionEndpoint)
    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "refresh-token",
            "token_type_hint": "refresh_token",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert not resp["active"]


def test_access_token_non_jwt_skipped(test_client, client, server):
    class MyIntrospectionEndpoint(IntrospectionEndpoint):
        def query_token(self, token, token_type_hint):
            return None

    server.register_endpoint(MyIntrospectionEndpoint)
    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "non-jwt-access-token",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert not resp["active"]


def test_permission_denied(test_client, introspection_endpoint, access_token, client):
    introspection_endpoint.check_permission = lambda *args: False

    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect", data={"token": access_token}, headers=headers
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert not resp["active"]


def test_token_expired(test_client, claims, client, jwks):
    claims["exp"] = time.time() - 3600
    access_token = create_access_token(claims, jwks)
    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect", data={"token": access_token}, headers=headers
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert not resp["active"]


def test_introspection_different_issuer(test_client, server, claims, client, jwks):
    class MyIntrospectionEndpoint(IntrospectionEndpoint):
        def query_token(self, token, token_type_hint):
            return None

    server.register_endpoint(MyIntrospectionEndpoint)

    claims["iss"] = "different-issuer"
    access_token = create_access_token(claims, jwks)
    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect", data={"token": access_token}, headers=headers
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert not resp["active"]


def test_introspection_invalid_claim(test_client, claims, client, jwks):
    claims["exp"] = "invalid"
    access_token = create_access_token(claims, jwks)
    headers = create_basic_header(client.client_id, client.client_secret)
    rv = test_client.post(
        "/oauth/introspect", data={"token": access_token}, headers=headers
    )
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"
