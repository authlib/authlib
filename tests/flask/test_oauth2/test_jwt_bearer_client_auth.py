import time

import pytest
from flask import json
from joserfc import jws
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7523 import client_secret_jwt_sign
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from tests.util import read_file_path


@pytest.fixture(autouse=True)
def server(server):
    class JWTClientCredentialsGrant(ClientCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            JWTBearerClientAssertion.CLIENT_AUTH_METHOD,
        ]

    server.register_grant(JWTClientCredentialsGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": JWTBearerClientAssertion.CLIENT_AUTH_METHOD,
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def register_jwt_client_auth(server, validate_jti=True, issuer=None):
    class JWTClientAuth(JWTBearerClientAssertion):
        def validate_jti(self, claims, jti):
            return jti != "used"

        def resolve_client_public_key(self, client, headers):
            if headers["alg"] == "RS256":
                return read_file_path("jwk_public.json")
            return client.client_secret

    server.register_client_auth_method(
        JWTClientAuth.CLIENT_AUTH_METHOD,
        JWTClientAuth("https://provider.test/oauth/token", validate_jti, issuer=issuer),
    )


def test_invalid_client(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_jwt(test_client, server):
    register_jwt_client_auth(server)

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="invalid-secret",
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_not_found_client(test_client, server):
    register_jwt_client_auth(server)

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="client-secret",
                client_id="invalid-client",
                token_endpoint="https://provider.test/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_not_supported_auth_method(test_client, server, client, db):
    register_jwt_client_auth(server)
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "invalid",
        }
    )
    db.session.add(client)
    db.session.commit()
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="client-secret",
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_client_secret_jwt(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="client-secret",
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
                claims={"jti": "nonce"},
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_private_key_jwt(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": private_key_jwt_sign(
                private_key=read_file_path("jwk_private.json"),
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_not_validate_jti(test_client, server):
    register_jwt_client_auth(server, validate_jti=False)

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="client-secret",
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_validate_jti_failed(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="client-secret",
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
                claims={"jti": "used"},
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "JWT ID" in resp["error_description"]


def test_invalid_assertion(test_client, server):
    register_jwt_client_auth(server)
    client_assertion = jws.serialize_compact(
        {"alg": "HS256"},
        "text",
        OctKey.import_key("client-secret"),
    )
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert "Invalid JWT" in resp["error_description"]


def test_missing_exp_claim(test_client, server):
    register_jwt_client_auth(server)
    key = OctKey.import_key("client-secret")
    # missing "exp" value
    claims = {
        "iss": "client-id",
        "sub": "client-id",
        "aud": "https://provider.test/oauth/token",
        "jti": "nonce",
    }
    client_assertion = jwt.encode({"alg": "HS256"}, claims, key)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert "error" in resp
    assert "'exp'" in resp["error_description"]


def test_iss_sub_not_same(test_client, server):
    register_jwt_client_auth(server)
    key = OctKey.import_key("client-secret")
    # missing "exp" value
    claims = {
        "sub": "client-id",
        "iss": "invalid-iss",
        "aud": "https://provider.test/oauth/token",
        "exp": int(time.time() + 3600),
        "jti": "nonce",
    }
    client_assertion = jwt.encode({"alg": "HS256"}, claims, key)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert "error" in resp
    assert resp["error_description"] == "Issuer and Subject MUST match."


def test_missing_jti(test_client, server):
    register_jwt_client_auth(server)
    key = OctKey.import_key("client-secret")
    # missing "exp" value
    claims = {
        "sub": "client-id",
        "iss": "client-id",
        "aud": "https://provider.test/oauth/token",
        "exp": int(time.time() + 3600),
    }
    client_assertion = jwt.encode({"alg": "HS256"}, claims, key)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert "error" in resp
    assert resp["error_description"] == "Missing JWT ID."


def test_issuer_as_audience(test_client, server):
    """Per RFC 7523 Section 3 and draft-ietf-oauth-rfc7523bis, the AS issuer
    identifier should be a valid audience value for client assertion JWTs."""
    register_jwt_client_auth(server, issuer="https://provider.test")
    key = OctKey.import_key("client-secret")
    claims = {
        "iss": "client-id",
        "sub": "client-id",
        "aud": "https://provider.test",
        "exp": int(time.time() + 3600),
        "jti": "nonce",
    }
    client_assertion = jwt.encode({"alg": "HS256"}, claims, key)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
