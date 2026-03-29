import json

import pytest

from authlib.oauth2.rfc6749.grants import (
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant,
)

from .models import Client
from .models import User
from .oauth2_server import create_basic_auth


@pytest.fixture(autouse=True)
def server(server):
    class PasswordGrant(_PasswordGrant):
        def authenticate_user(self, username, password):
            try:
                user = User.objects.get(username=username)
                if user.check_password(password):
                    return user
            except User.DoesNotExist:
                return None

    server.register_grant(PasswordGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        scope="",
        grant_type="password",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_invalid_client(factory, server):
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "foo", "password": "ok"},
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "foo", "password": "ok"},
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
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
            "scope": "invalid",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_scope"


def test_invalid_request(factory, server):
    auth_header = create_basic_auth("client-id", "client-secret")

    # case 1
    request = factory.get(
        "/oauth/token?grant_type=password",
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "unsupported_grant_type"

    # case 2
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"

    # case 3
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "foo"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"

    # case 4
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "wrong",
        },
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"


def test_unauthorized_client(factory, server, client):
    client.grant_type = "invalid"
    client.save()
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "unauthorized_client"


def test_authorize_token(factory, server):
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": "foo",
            "password": "ok",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert "access_token" in data
