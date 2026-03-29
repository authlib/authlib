import pytest
from flask import json

from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc6749.grants import (
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant,
)
from authlib.oidc.core import OpenIDToken

from .models import User
from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "openid profile",
            "grant_types": ["password"],
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


class IDToken(OpenIDToken):
    def get_jwt_config(self, grant, client):
        return {
            "iss": "Authlib",
            "key": "secret",
            "alg": "HS256",
        }

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


class PasswordGrant(_PasswordGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user.check_password(password):
            return user


def register_password_grant(server, extensions=None):
    server.register_grant(PasswordGrant, extensions)


def test_invalid_client(test_client, server):
    register_password_grant(
        server,
    )
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_scope(test_client, server):
    register_password_grant(
        server,
    )
    server.scopes_supported = ["profile"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
            "scope": "invalid",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_invalid_request(test_client, server):
    register_password_grant(
        server,
    )
    headers = create_basic_header("client-id", "client-secret")

    rv = test_client.get(
        add_params_to_uri(
            "/oauth/token",
            {
                "grant_type": "password",
            },
        ),
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_grant_type"

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "wrong",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_invalid_grant_type(test_client, server, db, client):
    register_password_grant(server)
    client.set_client_metadata(
        {
            "scope": "openid profile",
            "grant_types": ["invalid"],
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_authorize_token(test_client, server):
    register_password_grant(
        server,
    )
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_token_generator(test_client, server, app):
    m = "tests.flask.test_oauth2.oauth2_server:token_generator"
    app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
    server.load_config(app.config)
    register_password_grant(server)
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "c-password.1." in resp["access_token"]


def test_custom_expires_in(test_client, server, app):
    app.config.update({"OAUTH2_TOKEN_EXPIRES_IN": {"password": 1800}})
    server.load_config(app.config)
    register_password_grant(server)
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert resp["expires_in"] == 1800


def test_id_token_extension(test_client, server):
    register_password_grant(server, extensions=[IDToken()])
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
            "scope": "openid profile",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp
