import json

import pytest

from authlib.integrations.django_oauth2 import RevocationEndpoint

from .models import Client
from .oauth2_server import create_basic_auth

ENDPOINT_NAME = RevocationEndpoint.ENDPOINT_NAME


@pytest.fixture(autouse=True)
def server(server):
    server.register_endpoint(RevocationEndpoint)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_invalid_client(factory, server):
    request = factory.post("/oauth/revoke")
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    request = factory.post("/oauth/revoke", HTTP_AUTHORIZATION="invalid token")
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    request = factory.post(
        "/oauth/revoke",
        HTTP_AUTHORIZATION=create_basic_auth("invalid", "client-secret"),
    )
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    request = factory.post(
        "/oauth/revoke",
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "invalid"),
    )
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"


def test_invalid_token(factory, server, token):
    auth_header = create_basic_auth("client-id", "client-secret")

    request = factory.post("/oauth/revoke", HTTP_AUTHORIZATION=auth_header)
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"

    # case 1
    request = factory.post(
        "/oauth/revoke",
        data={"token": "invalid-token"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    assert resp.status_code == 200

    # case 2
    request = factory.post(
        "/oauth/revoke",
        data={
            "token": "a1",
            "token_type_hint": "unsupported_token_type",
        },
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    data = json.loads(resp.content)
    assert data["error"] == "unsupported_token_type"

    # case 3
    request = factory.post(
        "/oauth/revoke",
        data={
            "token": "a1",
            "token_type_hint": "refresh_token",
        },
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    assert resp.status_code == 200


def test_revoke_token_with_hint(factory, server, token):
    revoke_token(server, factory, {"token": "a1", "token_type_hint": "access_token"})
    revoke_token(server, factory, {"token": "r1", "token_type_hint": "refresh_token"})


def test_revoke_token_without_hint(factory, server, token):
    revoke_token(server, factory, {"token": "a1"})
    revoke_token(server, factory, {"token": "r1"})


def revoke_token(server, factory, data):
    auth_header = create_basic_auth("client-id", "client-secret")

    request = factory.post(
        "/oauth/revoke",
        data=data,
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_endpoint_response(ENDPOINT_NAME, request)
    assert resp.status_code == 200
