import pytest
from flask import json

from authlib.oauth2.rfc8693 import ACCESS_TOKEN_TYPE
from authlib.oauth2.rfc8693 import ID_TOKEN_TYPE
from authlib.oauth2.rfc8693 import TOKEN_EXCHANGE_GRANT_TYPE
from authlib.oauth2.rfc8693 import InvalidTargetError
from authlib.oauth2.rfc8693 import TokenExchangeGrant as _TokenExchangeGrant

from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header


class TokenExchangeGrant(_TokenExchangeGrant):
    def authenticate_subject_token(self, subject_token, subject_token_type):
        if subject_token_type == ACCESS_TOKEN_TYPE:
            return Token.query.filter_by(access_token=subject_token).first()
        if subject_token_type == ID_TOKEN_TYPE and subject_token == "id-token":
            return {"sub": "foo"}

    def authenticate_user(self, subject_token):
        if isinstance(subject_token, dict):
            return User.query.filter_by(username=subject_token["sub"]).first()
        return subject_token.user

    def check_permission(self, client, subject_token, actor_token, scopes):
        return "denied" not in scopes


class ActorTokenExchangeGrant(TokenExchangeGrant):
    def authenticate_actor_token(self, actor_token, actor_token_type):
        return self.authenticate_subject_token(actor_token, actor_token_type)

    def check_permission(self, client, subject_token, actor_token, scopes):
        return actor_token is not None and actor_token.user.username == "actor"


class TargetTokenExchangeGrant(TokenExchangeGrant):
    def issue_token(
        self, subject_token, actor_token, requested_token_type, resource, audience
    ):
        if "https://unknown.test" in audience:
            raise InvalidTargetError()
        return {
            "access_token": f"{self.request.user.username}@{','.join(resource + audience)}",
            "issued_token_type": requested_token_type,
            "token_type": "N_A",
        }


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile email denied",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": [TOKEN_EXCHANGE_GRANT_TYPE],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def create_token(access_token, username="foo", scope="profile email"):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username)
        db.session.add(user)
        db.session.commit()
    db.session.add(
        Token(
            user_id=user.id,
            client_id="client-id",
            token_type="bearer",
            access_token=access_token,
            scope=scope,
            expires_in=3600,
        )
    )
    db.session.commit()
    return access_token


def exchange(test_client, query_string=None, **data):
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": TOKEN_EXCHANGE_GRANT_TYPE, **data},
        query_string=query_string,
        headers=create_basic_header("client-id", "client-secret"),
    )
    return rv.status_code, json.loads(rv.data)


def test_exchange_for_access_token(app, test_client, server):
    app.config.update({"OAUTH2_REFRESH_TOKEN_GENERATOR": True})
    server.load_config(app.config)
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        requested_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    assert status == 200
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert resp["token_type"] == "Bearer"
    assert resp["scope"] == "profile"
    assert "refresh_token" not in resp
    token = Token.query.filter_by(access_token=resp["access_token"]).first()
    assert token.user.username == "foo"


def test_scope_defaults_to_subject_token(test_client, server):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token", scope="profile")

    status, resp = exchange(
        test_client, subject_token="subject-token", subject_token_type=ACCESS_TOKEN_TYPE
    )
    assert status == 200
    assert resp["scope"] == "profile"


def test_scope_exceeds_subject_token(test_client, server):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token", scope="profile")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile email",
    )
    assert status == 400
    assert resp["error"] == "invalid_scope"


def test_scope_of_another_token_type(test_client, server):
    server.register_grant(TokenExchangeGrant)

    status, resp = exchange(
        test_client,
        subject_token="id-token",
        subject_token_type=ID_TOKEN_TYPE,
        scope="email",
    )
    assert status == 200
    assert resp["scope"] == "email"


@pytest.mark.parametrize(
    "data,description",
    [
        (
            {"subject_token_type": ACCESS_TOKEN_TYPE},
            "Missing 'subject_token' in request",
        ),
        (
            {"subject_token": "subject-token", "subject_token_type": ""},
            "Missing 'subject_token_type' in request",
        ),
        (
            {
                "subject_token": "subject-token",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "actor_token": "actor-token",
            },
            "Missing 'actor_token_type' in request",
        ),
        (
            {
                "subject_token": "subject-token",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "actor_token_type": ACCESS_TOKEN_TYPE,
            },
            "'actor_token_type' must not be included without 'actor_token'",
        ),
        (
            {"subject_token": "unknown-token", "subject_token_type": ACCESS_TOKEN_TYPE},
            "Invalid 'subject_token'",
        ),
        (
            {"subject_token": "subject-token", "subject_token_type": ID_TOKEN_TYPE},
            "Invalid 'subject_token'",
        ),
        (
            {
                "subject_token": "denied-token",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "scope": "denied",
            },
            "The client is not allowed to exchange 'subject_token'",
        ),
        (
            {
                "subject_token": "subject-token",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "requested_token_type": ID_TOKEN_TYPE,
            },
            f"Unsupported 'requested_token_type': '{ID_TOKEN_TYPE}'",
        ),
        (
            {
                "subject_token": "subject-token",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "resource": "/api",
            },
            "Invalid 'resource' value: '/api'",
        ),
        (
            {
                "subject_token": "subject-token",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "resource": "https://backend.test/api#",
            },
            "Invalid 'resource' value: 'https://backend.test/api#'",
        ),
    ],
)
def test_invalid_request(test_client, server, data, description):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")
    create_token("denied-token", scope="denied")

    status, resp = exchange(test_client, **data)
    assert status == 400
    assert resp["error"] == "invalid_request"
    assert resp["error_description"] == description


def test_subject_token_in_query_string(test_client, server):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")

    status, resp = exchange(
        test_client,
        query_string={
            "subject_token": "subject-token",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
    )
    assert status == 400
    assert resp["error_description"] == "Missing 'subject_token' in request"


def test_empty_parameters_are_omitted(test_client, server):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        requested_token_type="",
        resource="",
        audience="",
    )
    assert status == 200
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE


@pytest.mark.parametrize(
    "target", [{"resource": "https://backend.test/api"}, {"audience": "backend"}]
)
def test_target_rejected_by_default(test_client, server, target):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        **target,
    )
    assert status == 400
    assert resp["error"] == "invalid_target"


def test_issue_token_for_targets(test_client, server):
    server.register_grant(TargetTokenExchangeGrant)
    create_token("subject-token")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        requested_token_type=ID_TOKEN_TYPE,
        resource=["https://a.test/api", "https://b.test/api?x=1"],
        audience="backend",
    )
    assert status == 200
    assert resp == {
        "access_token": "foo@https://a.test/api,https://b.test/api?x=1,backend",
        "issued_token_type": ID_TOKEN_TYPE,
        "token_type": "N_A",
    }

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        audience="https://unknown.test",
    )
    assert status == 400
    assert resp["error"] == "invalid_target"


def test_actor_token_rejected_by_default(test_client, server):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")
    create_token("actor-token", username="actor")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert resp["error_description"] == "Invalid 'actor_token'"


def test_actor_token(test_client, server):
    server.register_grant(ActorTokenExchangeGrant)
    create_token("subject-token")
    create_token("actor-token", username="actor")

    status, resp = exchange(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 200
    token = Token.query.filter_by(access_token=resp["access_token"]).first()
    assert token.user.username == "foo"

    status, resp = exchange(
        test_client, subject_token="subject-token", subject_token_type=ACCESS_TOKEN_TYPE
    )
    assert status == 400
    assert resp["error"] == "invalid_request"


def test_unknown_user(test_client, server):
    server.register_grant(TokenExchangeGrant)
    create_token("subject-token")
    db.session.delete(User.query.filter_by(username="foo").first())
    db.session.commit()

    status, resp = exchange(
        test_client, subject_token="subject-token", subject_token_type=ACCESS_TOKEN_TYPE
    )
    assert status == 400
    assert resp["error_description"] == "Invalid 'subject_token'"


def test_unauthorized_client(test_client, server, client):
    server.register_grant(TokenExchangeGrant)
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
        }
    )
    db.session.commit()
    create_token("subject-token")

    status, resp = exchange(
        test_client, subject_token="subject-token", subject_token_type=ACCESS_TOKEN_TYPE
    )
    assert status == 400
    assert resp["error"] == "unauthorized_client"


def test_invalid_client(test_client, server):
    server.register_grant(TokenExchangeGrant)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token": "subject-token",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        headers=create_basic_header("client-id", "invalid-secret"),
    )
    assert json.loads(rv.data)["error"] == "invalid_client"
