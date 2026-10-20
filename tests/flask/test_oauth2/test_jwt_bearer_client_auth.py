import time

import pytest
from flask import json
from joserfc import jws
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7523 import client_secret_jwt_sign
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from tests.util import HMAC_SECRET
from tests.util import read_file_path

secret_key = OctKey.import_key(HMAC_SECRET)


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
    client.client_secret = HMAC_SECRET
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


def register_jwt_client_auth(server, validate_jti=True, public_key=None):
    class JWTClientAuth(JWTBearerClientAssertion):
        def get_audiences(self):
            return ["https://provider.test/oauth/token"]

        def validate_jti(self, claims, jti):
            return jti != "used"

        def resolve_client_public_key(self, client):
            return public_key or OctKey.import_key(client.client_secret)

    server.register_client_auth_method(
        JWTClientAuth.CLIENT_AUTH_METHOD,
        JWTClientAuth(validate_jti=validate_jti),
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
                client_secret=OctKey.import_key("an-invalid-hmac-secret-32-bytes!"),
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
                client_secret=secret_key,
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
                client_secret=secret_key,
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
                client_secret=secret_key,
                client_id="client-id",
                token_endpoint="https://provider.test/oauth/token",
                claims={"jti": "nonce"},
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_private_key_jwt(test_client, server):
    register_jwt_client_auth(
        server, public_key=RSAKey.import_key(read_file_path("jwk_public.json"))
    )
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": private_key_jwt_sign(
                private_key=RSAKey.import_key(read_file_path("jwk_private.json")),
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
                client_secret=secret_key,
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
                client_secret=secret_key,
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
        secret_key,
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
    key = secret_key
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
    key = secret_key
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
    key = secret_key
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

    class JWTClientAuth(JWTBearerClientAssertion):
        def get_audiences(self):
            return ["https://provider.test/oauth/token", "https://provider.test"]

        def validate_jti(self, claims, jti):
            return True

        def resolve_client_public_key(self, client):
            return OctKey.import_key(client.client_secret)

    server.register_client_auth_method(
        JWTClientAuth.CLIENT_AUTH_METHOD,
        JWTClientAuth(),
    )

    key = secret_key
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


def test_malformed_assertion(test_client, server):
    """A 'client_assertion' that is not a compact JWS is rejected with an OAuth
    error."""
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": "not-a-jwt",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"
    assert resp["error_description"] == "Invalid JWT assertion."


def test_non_object_payload_assertion(test_client, server):
    """An assertion payload that is valid JSON but not a JSON object cannot
    hold claims."""
    register_jwt_client_auth(server)
    client_assertion = jws.serialize_compact(
        {"alg": "HS256"},
        '["client-id"]',
        secret_key,
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
    assert resp["error"] == "invalid_client"
    assert resp["error_description"] == "Invalid JWT payload."


def test_missing_sub_claim(test_client, server):
    """The 'sub' claim is read before the claims are verified, so its absence
    must be reported as an OAuth error."""
    register_jwt_client_auth(server)
    claims = {
        "iss": "client-id",
        "aud": "https://provider.test/oauth/token",
        "exp": int(time.time() + 3600),
        "jti": "nonce",
    }
    client_assertion = jwt.encode({"alg": "HS256"}, claims, secret_key)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"
    assert resp["error_description"] == "Missing claim: 'sub'"


def test_non_string_sub_claim(test_client, server):
    """A non-string 'sub' claim must not reach 'query_client'."""
    register_jwt_client_auth(server)
    claims = {
        "iss": "client-id",
        "sub": {"client_id": "client-id"},
        "aud": "https://provider.test/oauth/token",
        "exp": int(time.time() + 3600),
        "jti": "nonce",
    }
    client_assertion = jwt.encode({"alg": "HS256"}, claims, secret_key)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"
    assert resp["error_description"] == "Invalid claim: 'sub'"


def test_resolve_client_public_key_with_headers(test_client, server):
    """The former 'resolve_client_public_key(client, headers)' signature is
    still supported but deprecated."""

    class JWTClientAuth(JWTBearerClientAssertion):
        def get_audiences(self):
            return ["https://provider.test/oauth/token"]

        def validate_jti(self, claims, jti):
            return True

        def resolve_client_public_key(self, client, headers):
            return OctKey.import_key(client.client_secret)

    server.register_client_auth_method(
        JWTClientAuth.CLIENT_AUTH_METHOD, JWTClientAuth()
    )
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
        "client_assertion": client_secret_jwt_sign(
            client_secret=secret_key,
            client_id="client-id",
            token_endpoint="https://provider.test/oauth/token",
        ),
    }
    with pytest.warns(AuthlibDeprecationWarning, match="only 'client' parameter"):
        rv = test_client.post("/oauth/token", data=data)
    assert "access_token" in json.loads(rv.data)


@pytest.mark.filterwarnings(
    "ignore:Using implicit key type is not recommended:joserfc.errors.SecurityWarning"
)
def test_client_secret_jwt_with_raw_keys(test_client, server):
    """Raw secrets are still accepted to sign and verify the assertion but
    deprecated."""

    class JWTClientAuth(JWTBearerClientAssertion):
        def get_audiences(self):
            return ["https://provider.test/oauth/token"]

        def validate_jti(self, claims, jti):
            return True

        def resolve_client_public_key(self, client):
            return client.client_secret

    server.register_client_auth_method(
        JWTClientAuth.CLIENT_AUTH_METHOD, JWTClientAuth()
    )
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        client_assertion = client_secret_jwt_sign(
            client_secret=HMAC_SECRET,
            client_id="client-id",
            token_endpoint="https://provider.test/oauth/token",
        )
    data = {
        "grant_type": "client_credentials",
        "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
        "client_assertion": client_assertion,
    }
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        rv = test_client.post("/oauth/token", data=data)
    assert "access_token" in json.loads(rv.data)
