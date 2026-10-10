import time

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
    def get_audiences(self):
        return ["https://provider.test/token", "https://provider.test"]

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


def test_jwt_bearer_token_generator_casts_sub_to_string(client, user):
    """The generated JWT ``sub`` must be a string (RFC 7519 Section 4.1.2), even
    when ``get_user_id()`` returns a non-string such as an integer primary key.
    ``joserfc`` 1.7.3 rejects non-string ``sub`` claims."""
    generator = JWTBearerTokenGenerator(
        read_file_path("jwks_private.json"), issuer="https://provider.test"
    )
    token = generator.generate(
        JWTBearerGrant.GRANT_TYPE, client, user=user, scope="profile"
    )
    claims = jwt.decode(
        token["access_token"], generator.secret_key, algorithms=["RS256"]
    ).claims
    assert isinstance(user.get_user_id(), int)
    assert claims["sub"] == str(user.get_user_id())


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


@pytest.mark.parametrize(
    "audience",
    ["https://evil.test/token", ["https://evil.test/token", "https://other.test"]],
)
def test_invalid_audience(test_client, audience):
    """RFC 7523 Section 3: The authorization server MUST reject any JWT that
    does not contain its own identity as the intended audience."""

    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience=audience,
        subject=None,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


@pytest.mark.parametrize(
    "audience",
    ["https://provider.test", ["https://other.test", "https://provider.test/token"]],
)
def test_valid_audience(test_client, audience):
    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience=audience,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    assert "access_token" in json.loads(rv.data)


@pytest.mark.parametrize("audiences", [None, []])
def test_missing_audience_configuration(test_client, monkeypatch, audiences):
    if audiences is None:
        monkeypatch.setattr(
            JWTBearerGrant, "get_audiences", _JWTBearerGrant.get_audiences
        )
    else:
        monkeypatch.setattr(JWTBearerGrant, "get_audiences", lambda self: audiences)

    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="client-id",
        audience="https://provider.test/token",
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert "audience" in resp["error_description"]
    assert "access_token" not in resp


def test_malformed_assertion(test_client):
    """An 'assertion' that is not a compact JWS is rejected with an OAuth
    error."""
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": "not-a-jwt"},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert resp["error_description"] == "Invalid JWT assertion."


def test_non_object_payload_assertion(test_client):
    """An assertion payload that is valid JSON but not a JSON object cannot
    hold claims."""
    assertion = jws.serialize_compact(
        {"alg": "HS256", "kid": "1"},
        '["client-id"]',
        OctKey.import_key("foo"),
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert resp["error_description"] == "Invalid JWT payload."


def test_missing_iss_claim(test_client):
    """The 'iss' claim is read before the claims are verified, so its absence
    must be reported as an OAuth error."""
    assertion = jwt.encode(
        {"alg": "HS256", "kid": "1"},
        {"aud": "https://provider.test/token", "exp": int(time.time() + 3600)},
        OctKey.import_key("foo"),
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert resp["error_description"] == "Missing claim: 'iss'"


def test_non_string_iss_claim(test_client):
    """A non-string 'iss' claim must not reach 'resolve_issuer_client'."""
    assertion = jwt.encode(
        {"alg": "HS256", "kid": "1"},
        {
            "iss": ["client-id"],
            "aud": "https://provider.test/token",
            "exp": int(time.time() + 3600),
        },
        OctKey.import_key("foo"),
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert resp["error_description"] == "Invalid claim: 'iss'"


def test_unknown_issuer(test_client):
    """'resolve_issuer_client' returning None yields an 'invalid_grant'
    error."""
    assertion = JWTBearerGrant.sign(
        "foo",
        issuer="unknown-client",
        audience="https://provider.test/token",
        subject=None,
        header={"alg": "HS256", "kid": "1"},
    )
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert resp["error_description"] == "The client does not exist on this server."
