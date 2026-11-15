import time

import pytest
from flask import json

from authlib.integrations.sqla_oauth2 import create_query_token_func
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header

query_token = create_query_token_func(db.session, Token)


class MyIntrospectionEndpoint(IntrospectionEndpoint):
    def check_permission(self, token, client, request):
        return True

    def query_token(self, token, token_type_hint):
        return query_token(token, token_type_hint)

    def introspect_token(self, token):
        user = db.session.get(User, token.user_id)
        return {
            "active": True,
            "client_id": token.client_id,
            "username": user.username,
            "scope": token.scope,
            "sub": user.get_user_id(),
            "aud": token.client_id,
            "iss": "https://provider.test/",
            "exp": token.issued_at + token.expires_in,
            "iat": token.issued_at,
        }


@pytest.fixture(autouse=True)
def server(server, app):
    server.register_endpoint(MyIntrospectionEndpoint)

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response("introspection")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/callback"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_invalid_client(test_client):
    rv = test_client.post("/oauth/introspect")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = {"Authorization": "invalid token_string"}
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("invalid-client", "client-secret")
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_token(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/introspect", headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token_type_hint": "refresh_token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
            "token_type_hint": "unsupported_token_type",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert "error" not in resp

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "invalid-token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["active"] is False

    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
            "token_type_hint": "refresh_token",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["active"] is False


def test_introspect_token_with_hint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
            "token_type_hint": "access_token",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"


def test_introspect_token_without_hint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={
            "token": "a1",
        },
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"


def test_introspect_token_with_wrong_hint(test_client, token):
    """Per RFC 7662 §2.1, the search is extended when the hint does not match."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": token.refresh_token, "token_type_hint": "access_token"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"]


def test_introspect_token_with_unknown_hint(test_client, token):
    """Per RFC 7662 §2.1, an unknown token type hint is ignored."""
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "a1", "token_type_hint": "unknown"},
        headers=headers,
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["active"]


def _introspect(test_client, token_string, hint=None):
    data = {"token": token_string}
    if hint:
        data["token_type_hint"] = hint
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/introspect", data=data, headers=headers)
    assert rv.status_code == 200
    return json.loads(rv.data)


@pytest.mark.parametrize("hint", [None, "refresh_token"])
def test_introspect_refresh_token_with_expired_access_token(
    test_client, token, db, hint
):
    """The refresh token has its own lifetime (RFC 7662 §2.1)."""
    token.issued_at = int(time.time()) - 7200
    token.refresh_token_expires_at = int(time.time()) + 3600
    db.session.commit()

    assert _introspect(test_client, "r1", hint)["active"] is True
    assert _introspect(test_client, "a1", "access_token") == {"active": False}


def test_introspect_expired_refresh_token(test_client, token, db):
    token.issued_at = int(time.time()) - 7200
    token.refresh_token_expires_at = int(time.time()) - 60
    db.session.commit()

    assert _introspect(test_client, "r1", "refresh_token") == {"active": False}
    assert _introspect(test_client, "r1") == {"active": False}


def test_introspect_access_token_ignores_refresh_token_expiry(test_client, token, db):
    token.refresh_token_expires_at = int(time.time()) - 60
    db.session.commit()

    assert _introspect(test_client, "a1")["active"] is True
    assert _introspect(test_client, "a1", "access_token")["active"] is True


def test_refresh_token_expiry_defaults():
    from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
    from authlib.oauth2.rfc6749 import TokenMixin

    class PlainToken(TokenMixin):
        def is_expired(self):
            return True

    # Without an override, the refresh token follows the access token.
    assert PlainToken().is_refresh_token_expired() is True
    # The SQLAlchemy mixin has no refresh token lifetime.
    assert OAuth2TokenMixin.is_refresh_token_expired(Token()) is False
