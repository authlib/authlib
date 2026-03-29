import json
import time

import pytest

from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant

from .models import Client
from .models import OAuth2Token
from .oauth2_server import create_basic_auth


@pytest.fixture(autouse=True)
def server(server):
    class RefreshTokenGrant(_RefreshTokenGrant):
        def authenticate_refresh_token(self, refresh_token):
            try:
                item = OAuth2Token.objects.get(refresh_token=refresh_token)
                if item.is_refresh_token_active():
                    return item
            except OAuth2Token.DoesNotExist:
                return None

        def authenticate_user(self, credential):
            return credential.user

        def revoke_old_credential(self, credential):
            now = int(time.time())
            credential.access_token_revoked_at = now
            credential.refresh_token_revoked_at = now
            credential.save()
            return credential

    server.register_grant(RefreshTokenGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        scope="",
        grant_type="refresh_token",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_invalid_client(factory, server):
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": "foo"},
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": "foo"},
        HTTP_AUTHORIZATION=create_basic_auth("invalid", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 401
    data = json.loads(resp.content)
    assert data["error"] == "invalid_client"


def test_invalid_refresh_token(factory, server):
    auth_header = create_basic_auth("client-id", "client-secret")
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "refresh_token"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_request"
    assert "Missing" in data["error_description"]

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": "invalid"},
        HTTP_AUTHORIZATION=auth_header,
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_grant"


def test_invalid_scope(factory, server, token):
    server.scopes_supported = ["profile"]
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "invalid",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 400
    data = json.loads(resp.content)
    assert data["error"] == "invalid_scope"


def test_authorize_tno_scope(factory, server, token):
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert "access_token" in data


def test_authorize_token_scope(factory, server, token):
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert "access_token" in data


def test_revoke_old_token(factory, server, token):
    request = factory.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r1",
            "scope": "profile",
        },
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert "access_token" in data

    resp = server.create_token_response(request)
    assert resp.status_code == 400
