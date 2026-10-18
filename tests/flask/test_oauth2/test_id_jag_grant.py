import time

import pytest
from flask import json
from joserfc.jwk import RSAKey

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.drafts import IDJAGGrant as _IDJAGGrant
from authlib.oauth2.rfc6749 import InvalidGrantError
from tests.util import read_file_path

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header

private_pem = read_file_path("rsa_private.pem")
public_pem = read_file_path("rsa_public.pem")
rsa_private = RSAKey.import_key(private_pem)
rsa_public = RSAKey.import_key(public_pem)

# Simulated trusted-issuer registry and JTI replay store
_TRUSTED_ISSUERS = {"https://idp.example.com": rsa_public}
_USED_JTIS: set = set()


class IDJAGGrant(_IDJAGGrant):
    """Concrete ID-JAG grant wired to the Flask test models."""

    def get_audiences(self):
        return ["https://provider.test/token"]

    def resolve_issuer_key(self, issuer, headers):
        key = _TRUSTED_ISSUERS.get(issuer)
        if key is None:
            raise InvalidGrantError(description="Untrusted issuer")
        return key

    def authenticate_user(self, subject):
        return User.query.filter_by(username=subject).first()

    def check_jti(self, claims, jti):
        if jti in _USED_JTIS:
            return False
        _USED_JTIS.add(jti)
        return True

    def check_id_jag_permission(self, client, user, scopes):
        return True


# -- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_jti_store():
    _USED_JTIS.clear()


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(IDJAGGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": [IDJAGGrant.GRANT_TYPE],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def _sign(**overrides):
    """Produce a valid ID-JAG assertion for the test fixtures."""
    defaults = dict(
        key=rsa_private,
        issuer="https://idp.example.com",
        audience="https://provider.test/token",
        subject="foo",  # matches User.username created by conftest
        client_id="client-id",  # matches Client.client_id from conftest
        alg="RS256",
    )
    defaults.update(overrides)
    return IDJAGGrant.sign(**defaults)


# -- tests -------------------------------------------------------------------


def test_missing_assertion(test_client):
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert "assertion" in resp["error_description"]


def test_valid_id_jag_flow(test_client):
    assertion = _sign()
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "refresh_token" not in resp


@pytest.mark.filterwarnings(
    "ignore:Using implicit key type is not recommended:joserfc.errors.SecurityWarning"
)
def test_sign_with_raw_key(test_client):
    """A raw PEM key is still accepted to sign the assertion but deprecated."""
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        assertion = _sign(key=private_pem)
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    assert "access_token" in json.loads(rv.data)


def test_wrong_typ_header(test_client):
    """Standard JWT (typ: JWT) must be rejected."""
    from joserfc import jwt

    token_str = jwt.encode(
        {"alg": "RS256", "typ": "JWT"},
        {
            "iss": "https://idp.example.com",
            "sub": "foo",
            "aud": "https://provider.test/token",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "jti": "jti-typ-test",
            "client_id": "client-id",
        },
        rsa_private,
    )
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert "typ" in resp["error_description"]


def test_untrusted_issuer(test_client):
    assertion = _sign(issuer="https://evil.example.com")
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_invalid_signature(test_client):
    wrong_key = RSAKey.generate_key(2048)
    assertion = _sign(key=wrong_key)
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_audience_mismatch(test_client):
    assertion = _sign(audience="https://evil.test/token")
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_unknown_client_claim(test_client):
    assertion = _sign(client_id="unknown-client")
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert "client_id" in resp["error_description"]


def test_invalid_subject(test_client):
    assertion = _sign(subject="nonexistent-user")
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert "sub" in resp["error_description"]


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

    assertion = _sign()
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_expired_assertion(test_client):
    assertion = _sign(
        issued_at=int(time.time()) - 7200,
        expires_at=int(time.time()) - 3600,
    )
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_jti_replay_rejected(test_client):
    assertion = _sign(jti="replay-jti")
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp

    # Same jti again
    assertion2 = _sign(jti="replay-jti")
    rv2 = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion2},
    )
    resp2 = json.loads(rv2.data)
    assert resp2["error"] == "invalid_grant"
    assert "jti" in resp2["error_description"]


def test_policy_denial(test_client, server):
    class DenyGrant(IDJAGGrant):
        def check_id_jag_permission(self, client, user, scopes):
            return False

    server._token_grants.clear()
    server.register_grant(DenyGrant)

    assertion = _sign()
    rv = test_client.post(
        "/oauth/token",
        headers=create_basic_header("client-id", "client-secret"),
        data={"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"
    assert "ermission" in resp["error_description"]


@pytest.fixture
def other_client(db, user):
    client = Client(
        user_id=user.id, client_id="other-client", client_secret="other-secret"
    )
    client.set_client_metadata(
        {
            "scope": "profile",
            "grant_types": [IDJAGGrant.GRANT_TYPE],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.mark.parametrize(
    "auth_case",
    [
        "absent",
        "client_id_only",
        "wrong_secret",
        "unknown_client",
        "different_client",
    ],
)
def test_id_jag_requires_matching_client_authentication(
    test_client, other_client, auth_case
):
    assertion = _sign(jti="client-auth-regression")
    data = {"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion}
    headers = {}
    if auth_case == "client_id_only":
        data["client_id"] = "client-id"
    elif auth_case == "wrong_secret":
        headers = create_basic_header("client-id", "wrong-secret")
    elif auth_case == "unknown_client":
        headers = create_basic_header("unknown-client", "client-secret")
    elif auth_case == "different_client":
        headers = create_basic_header("other-client", "other-secret")

    response = test_client.post("/oauth/token", data=data, headers=headers)
    if auth_case == "different_client":
        assert response.status_code == 400
        assert response.json["error"] == "invalid_grant"
        assert "client_id" in response.json["error_description"]
    else:
        assert response.status_code == 401
        assert response.json["error"] == "invalid_client"
    assert "access_token" not in response.json
    assert Token.query.count() == 0
    assert "client-auth-regression" not in _USED_JTIS

    # A rejected requester must not consume the legitimate client's assertion.
    response = test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert response.status_code == 200
    assert "access_token" in response.json
    assert "refresh_token" not in response.json
    assert Token.query.one().client_id == "client-id"


def test_public_client_cannot_redeem_id_jag_by_default(test_client, client, db):
    client.client_secret = ""
    client.set_client_metadata(
        {
            **client.client_metadata,
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.commit()
    response = test_client.post(
        "/oauth/token",
        data={
            "grant_type": IDJAGGrant.GRANT_TYPE,
            "assertion": _sign(),
            "client_id": "client-id",
        },
    )
    assert response.status_code == 401
    assert response.json["error"] == "invalid_client"
    assert Token.query.count() == 0


@pytest.mark.parametrize("secret", ["client-secret", "wrong-secret"])
def test_id_jag_client_secret_post(test_client, server, client, db, secret):
    class PostIDJAGGrant(IDJAGGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_post"]

    server._token_grants.clear()
    server.register_grant(PostIDJAGGrant)
    client.set_client_metadata(
        {
            **client.client_metadata,
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db.session.commit()
    response = test_client.post(
        "/oauth/token",
        data={
            "grant_type": IDJAGGrant.GRANT_TYPE,
            "assertion": _sign(),
            "client_id": "client-id",
            "client_secret": secret,
        },
    )
    if secret == "client-secret":
        assert response.status_code == 200
        assert "access_token" in response.json
        assert Token.query.one().client_id == "client-id"
    else:
        assert response.status_code == 400
        assert response.json["error"] == "invalid_client"
        assert Token.query.count() == 0
