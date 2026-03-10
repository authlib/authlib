import pytest
from flask import json
from joserfc import jws
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib.oauth2.rfc7523 import JWTBearerGrant as _JWTBearerGrant
from authlib.oauth2.rfc7523 import JWTBearerTokenGenerator
from tests.util import read_file_path

from .models import Client
from .models import db


class JWTBearerGrant(_JWTBearerGrant):
    def resolve_issuer_client(self, issuer):
        return Client.query.filter_by(client_id=issuer).first()

    def resolve_client_public_key(self, client):
        return KeySet(
            [
                OctKey.import_key("foo", {"kid": "1"}),
                OctKey.import_key("bar", {"kid": "2"}),
            ]
        )

    def authenticate_user(self, subject):
        return None

    def has_granted_permission(self, client, user):
        return True


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(JWTBearerGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": [JWTBearerGrant.GRANT_TYPE],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_missing_assertion(test_client):
    rv = test_client.post(
        "/oauth/token", data={"grant_type": JWTBearerGrant.GRANT_TYPE}
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "assertion" in resp["error_description"]


def test_invalid_assertion(test_client):
    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience="https://provider.test/token",
        subject="none",
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_authorize_token(test_client):
    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience="https://provider.test/token",
        subject=None,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_unauthorized_client(test_client, client):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["password"],
        }
    )
    db.session.add(client)
    db.session.commit()

    assertion = JWTBearerGrant.sign(
        "bar",
        issuer="client-id",
        audience="https://provider.test/token",
        subject=None,
        header={"alg": "HS256", "kid": "2"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_token_generator(test_client, app, server):
    m = "tests.flask.test_oauth2.oauth2_server:token_generator"
    app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
    server.load_config(app.config)
    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience="https://provider.test/token",
        subject=None,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "c-" in resp["access_token"]


def test_jwt_bearer_token_generator(test_client, server):
    private_key = read_file_path("jwks_private.json")
    server.register_token_generator(
        JWTBearerGrant.GRANT_TYPE,
        JWTBearerTokenGenerator(private_key),
    )
    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience="https://provider.test/token",
        subject=None,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert resp["access_token"].count(".") == 2


def test_invalid_payload_assertion(test_client):
    assertion = jws.serialize_compact(
        {"alg": "HS256", "kid": "1"},
        "text",
        OctKey.import_key("foo"),
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "Invalid JWT" in resp["error_description"]


def test_missing_assertion_claims(test_client):
    assertion = jwt.encode(
        {"alg": "HS256", "kid": "1"},
        {"iss": "client-id"},
        OctKey.import_key("foo"),
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "Missing claim" in resp["error_description"]


def test_invalid_audience(test_client, server):
    """RFC 7523 Section 3: The authorization server MUST reject any JWT that
    does not contain its own identity as the intended audience."""

    class StrictAudienceGrant(JWTBearerGrant):
        def get_audiences(self):
            return ["https://provider.test/token"]

    server._token_grants.clear()
    server.register_grant(StrictAudienceGrant)
    assertion = StrictAudienceGrant.sign(
        "foo",
        issuer="client-id",
        audience="https://evil.test/token",
        subject=None,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": StrictAudienceGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
