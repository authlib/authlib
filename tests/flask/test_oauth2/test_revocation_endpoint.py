import pytest
from flask import json

from authlib.integrations.sqla_oauth2 import create_revocation_endpoint

from .models import Client
from .models import Token
from .models import db
from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def server(server, app):
    RevocationEndpoint = create_revocation_endpoint(db.session, Token)
    server.register_endpoint(RevocationEndpoint)

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return server.create_endpoint_response("revocation")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_invalid_client(test_client):
    rv = test_client.post("/oauth/revoke")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = {"Authorization": "invalid token_string"}
    rv = test_client.post("/oauth/revoke", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("invalid-client", "client-secret")
    rv = test_client.post("/oauth/revoke", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post("/oauth/revoke", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_token(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/revoke", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/revoke",
        data={
            "token": "invalid-token",
        },
        headers=headers,
    )
    assert rv.status_code == 200

    rv = test_client.post(
        "/oauth/revoke",
        data={
            "token": "a1",
            "token_type_hint": "unsupported_token_type",
        },
        headers=headers,
    )
    assert rv.status_code == 200

    rv = test_client.post(
        "/oauth/revoke",
        data={
            "token": "a1",
            "token_type_hint": "refresh_token",
        },
        headers=headers,
    )
    assert rv.status_code == 200


def test_revoke_token_with_hint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/revoke",
        data={
            "token": "a1",
            "token_type_hint": "access_token",
        },
        headers=headers,
    )
    assert rv.status_code == 200


def test_revoke_token_without_hint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/revoke",
        data={
            "token": "a1",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    assert token.is_revoked()
    assert token.is_refresh_token_active()


def test_revoke_refresh_token_without_hint(test_client, token):
    """Per RFC 7009 §2.1, revoking a refresh token also revokes the access
    token."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/revoke",
        data={"token": token.refresh_token},
        headers=headers,
    )
    assert rv.status_code == 200
    assert token.is_revoked()
    assert not token.is_refresh_token_active()


def test_revoke_token_bound_to_client(test_client, token):
    client2 = Client(
        user_id=1,
        client_id="client-id-2",
        client_secret="client-secret-2",
    )
    client2.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client2)
    db.session.commit()

    headers = create_basic_header("client-id-2", "client-secret-2")
    rv = test_client.post(
        "/oauth/revoke",
        data={
            "token": "a1",
        },
        headers=headers,
    )
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_insecure_transport(test_client, monkeypatch):
    with monkeypatch.context() as m:
        m.delenv("AUTHLIB_INSECURE_TRANSPORT")
        rv = test_client.post("/oauth/revoke", base_url="http://client.test")
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "insecure_transport"


def test_revoke_with_unknown_hint(test_client, client, token):
    """Per RFC 7009 §2.2, an unknown token type hint is ignored."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/revoke",
        data={"token": token.access_token, "token_type_hint": "unknown"},
        headers=headers,
    )
    assert rv.status_code == 200
    assert token.is_revoked()


def test_revoke_with_wrong_hint(test_client, token):
    """Per RFC 7009 §2.1, the search is extended when the hint does not match."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/revoke",
        data={"token": token.refresh_token, "token_type_hint": "access_token"},
        headers=headers,
    )
    assert rv.status_code == 200
    assert not token.is_refresh_token_active()
