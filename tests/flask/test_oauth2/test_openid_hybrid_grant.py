import pytest
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core.grants import OpenIDHybridGrant as _OpenIDHybridGrant

from .models import CodeGrantMixin
from .models import exists_nonce
from .models import save_authorization_code
from .oauth2_server import create_basic_header

JWT_CONFIG = {"iss": "Authlib", "key": "secret", "alg": "HS256", "exp": 3600}


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    class OpenIDCode(_OpenIDCode):
        def get_jwt_config(self, grant, client):
            return dict(JWT_CONFIG)

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

    class OpenIDHybridGrant(_OpenIDHybridGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

        def get_jwt_config(self, client):
            return dict(JWT_CONFIG)

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

    server.register_grant(OpenIDHybridGrant)
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode()])

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile address",
            "response_types": [
                "code id_token",
                "code token",
                "code id_token token",
            ],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def validate_claims(id_token, params):
    claims = jwt.decode(
        id_token, "secret", claims_cls=HybridIDToken, claims_params=params
    )
    claims.validate()


def test_invalid_client_id(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "invalid-client",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_require_nonce(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "scope": "openid profile",
            "state": "bar",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "error=invalid_request" in rv.location
    assert "nonce" in rv.location


def test_invalid_response_type(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token invalid",
            "state": "bar",
            "nonce": "abc",
            "scope": "profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "unsupported_response_type"


def test_invalid_scope(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token",
            "state": "bar",
            "nonce": "abc",
            "scope": "profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "error=invalid_scope" in rv.location


def test_access_denied(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
        },
    )
    assert "error=access_denied" in rv.location


def test_code_access_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "access_token=" in rv.location
    assert "id_token=" not in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp


def test_code_id_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "id_token=" in rv.location
    assert "access_token=" not in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"

    params["nonce"] = "abc"
    params["client_id"] = "client-id"
    validate_claims(params["id_token"], params)

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp


def test_code_id_token_access_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "id_token=" in rv.location
    assert "access_token=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"
    validate_claims(params["id_token"], params)

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp


def test_response_mode_query(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token token",
            "response_mode": "query",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "id_token=" in rv.location
    assert "access_token=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "bar"


def test_response_mode_form_post(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token token",
            "response_mode": "form_post",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert b'name="code"' in rv.data
    assert b'name="id_token"' in rv.data
    assert b'name="access_token"' in rv.data
