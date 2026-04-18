import pytest
from flask import json
from flask import jsonify

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator

from .models import Token
from .oauth2_server import create_bearer_header


@pytest.fixture(autouse=True)
def server(server):
    return server


@pytest.fixture(autouse=True)
def resource_server(app, db):
    require_oauth = ResourceProtector()
    BearerTokenValidator = create_bearer_token_validator(db.session, Token)
    require_oauth.register_token_validator(BearerTokenValidator())

    @app.route("/user")
    @require_oauth("profile")
    def user_profile():
        user = current_token.user
        return jsonify(id=user.id, username=user.username)

    @app.route("/user/email")
    @require_oauth("email")
    def user_email():
        user = current_token.user
        return jsonify(email=user.username + "@example.com")

    @app.route("/info")
    @require_oauth()
    def public_info():
        return jsonify(status="ok")

    @app.route("/no-parens")
    @require_oauth
    def no_parens():
        return jsonify(status="ok")

    @app.route("/operator-and")
    @require_oauth(["profile email"])
    def operator_and():
        return jsonify(status="ok")

    @app.route("/operator-or")
    @require_oauth(["profile", "email"])
    def operator_or():
        return jsonify(status="ok")

    @app.route("/acquire")
    def test_acquire():
        with require_oauth.acquire("profile") as token:
            user = token.user
            return jsonify(id=user.id, username=user.username)

    @app.route("/optional")
    @require_oauth("profile", optional=True)
    def test_optional_token():
        if current_token:
            user = current_token.user
            return jsonify(id=user.id, username=user.username)
        else:
            return jsonify(id=0, username="anonymous")

    return require_oauth


def test_authorization_none_grant(test_client):
    authorize_url = "/oauth/authorize?response_type=token&client_id=implicit-client"
    rv = test_client.get(authorize_url)
    assert b"unsupported_response_type" in rv.data

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert rv.status != 200

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "x",
        },
    )
    data = json.loads(rv.data)
    assert data["error"] == "unsupported_grant_type"


def test_invalid_token(test_client, token):
    rv = test_client.get("/user")
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "missing_authorization"

    headers = {"Authorization": "invalid token"}
    rv = test_client.get("/user", headers=headers)
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "unsupported_token_type"

    headers = create_bearer_header("invalid")
    rv = test_client.get("/user", headers=headers)
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"


def test_expired_token(test_client, db, token):
    token.expires_in = -10
    db.session.add(token)
    db.session.commit()

    headers = create_bearer_header("a1")

    rv = test_client.get("/user", headers=headers)
    assert rv.status_code == 401
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_token"

    rv = test_client.get("/acquire", headers=headers)
    assert rv.status_code == 401


def test_insufficient_token(test_client, token):
    headers = create_bearer_header("a1")
    rv = test_client.get("/user/email", headers=headers)
    assert rv.status_code == 403
    resp = json.loads(rv.data)
    assert resp["error"] == "insufficient_scope"


def test_access_resource(test_client, token):
    headers = create_bearer_header("a1")

    rv = test_client.get("/user", headers=headers)
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"

    rv = test_client.get("/acquire", headers=headers)
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"

    rv = test_client.get("/info", headers=headers)
    resp = json.loads(rv.data)
    assert resp["status"] == "ok"

    rv = test_client.get("/no-parens", headers=headers)
    resp = json.loads(rv.data)
    assert resp["status"] == "ok"


def test_scope_operator(test_client, token):
    headers = create_bearer_header("a1")
    rv = test_client.get("/operator-and", headers=headers)
    assert rv.status_code == 403
    resp = json.loads(rv.data)
    assert resp["error"] == "insufficient_scope"

    rv = test_client.get("/operator-or", headers=headers)
    assert rv.status_code == 200


def test_optional_token(test_client, token):
    rv = test_client.get("/optional")
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["username"] == "anonymous"

    headers = create_bearer_header("a1")
    rv = test_client.get("/optional", headers=headers)
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["username"] == "foo"
