import time

import pytest
from flask import json

from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant

from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def server(server):
    class RefreshTokenGrant(_RefreshTokenGrant):
        def authenticate_refresh_token(self, refresh_token):
            item = Token.query.filter_by(refresh_token=refresh_token).first()
            if item and item.is_refresh_token_active():
                return item

        def authenticate_user(self, credential):
            return db.session.get(User, credential.user_id)

        def revoke_old_credential(self, credential):
            now = int(time.time())
            credential.access_token_revoked_at = now
            credential.refresh_token_revoked_at = now
            db.session.add(credential)
            db.session.commit()

    server.register_grant(RefreshTokenGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "grant_types": ["refresh_token"],
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_invalid_client(test_client):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "foo",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("invalid-client", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "foo",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "foo",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_refresh_token(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "Missing" in resp["error_description"]

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "foo",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_invalid_scope(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "invalid",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_invalid_scope_none(test_client, token):
    token.scope = None
    db.session.add(token)
    db.session.commit()

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "invalid",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_invalid_user(test_client, token):
    token.user_id = 5
    db.session.add(token)
    db.session.commit()

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_invalid_grant_type(test_client, client, db, token):
    client.set_client_metadata(
        {
            "scope": "profile",
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
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_authorize_token_no_scope(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_authorize_token_scope(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_revoke_old_credential(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        headers=headers,
    )
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_token_generator(test_client, token, app, server):
    m = "tests.flask.test_oauth2.oauth2_server:token_generator"
    app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
    server.load_config(app.config)

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "c-refresh_token.1." in resp["access_token"]
