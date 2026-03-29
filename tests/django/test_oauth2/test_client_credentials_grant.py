import json

import pytest

from authlib.oauth2.rfc6749 import grants

from .models import Client
from .oauth2_server import create_basic_auth


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(grants.ClientCredentialsGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        scope="",
        grant_type="client_credentials",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_invalid_client(factory, server):
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("invalid", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"


def test_invalid_scope(factory, server):
    server.scopes_supported = ["profile"]
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "invalid"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_scope"


def test_invalid_request(factory, server):
    request = factory.get(
        "/oauth/token?grant_type=client_credentials",
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "unsupported_grant_type"


def test_unauthorized_client(factory, server, client):
    client.grant_type = "invalid"
    client.save()
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "unauthorized_client"


def test_authorize_token(factory, server):
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert "access_token" in data
