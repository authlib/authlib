import pytest
from flask import json

from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant

from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(ClientCredentialsGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_invalid_client(test_client):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_grant_type(test_client, client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["invalid"],
        }
    )
    db.session.add(client)
    db.session.commit()
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_invalid_scope(test_client, server):
    server.scopes_supported = ["profile"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "scope": "invalid",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_authorize_token(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_token_generator(test_client, app, server):
    m = "tests.flask.test_oauth2.oauth2_server:token_generator"
    app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
    server.load_config(app.config)

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "c-client_credentials." in resp["access_token"]
