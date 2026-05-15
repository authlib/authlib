"""Test should_handle hook in JWTBearerClientAssertion."""
import time
from unittest.mock import MagicMock

from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7523.client import ASSERTION_TYPE

TOKEN_URL = "https://provider.test/oauth/token"
SYMMETRIC_ALGS = {"HS256", "HS384", "HS512"}


class ClientSecretJWTAuth(JWTBearerClientAssertion):
    CLIENT_AUTH_METHOD = "client_secret_jwt"

    def should_handle(self, headers, claims):
        return headers.get("alg") in SYMMETRIC_ALGS

    def get_audiences(self):
        return [TOKEN_URL]

    def validate_jti(self, claims, jti):
        return True

    def resolve_client_public_key(self, client):
        return client.symmetric_key


class PrivateKeyJWTAuth(JWTBearerClientAssertion):
    CLIENT_AUTH_METHOD = "private_key_jwt"

    def should_handle(self, headers, claims):
        return headers.get("alg") not in SYMMETRIC_ALGS

    def get_audiences(self):
        return [TOKEN_URL]

    def validate_jti(self, claims, jti):
        return True

    def resolve_client_public_key(self, client):
        return client.public_key


def _make_request(alg, key, client_id="test-client"):
    now = int(time.time())
    assertion = jwt.encode(
        {"alg": alg},
        {
            "iss": client_id,
            "sub": client_id,
            "aud": TOKEN_URL,
            "exp": now + 3600,
            "jti": "test-jti",
        },
        key,
    )
    req = MagicMock()
    req.form = {
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }
    return req


def _make_client(symmetric_key=None, public_key=None):
    client = MagicMock()
    client.symmetric_key = symmetric_key
    client.public_key = public_key
    client.check_endpoint_auth_method.return_value = True
    return client


def test_client_secret_jwt_accepts_hs256():
    """client_secret_jwt handler accepts and verifies HS256 assertion."""
    oct_key = OctKey.import_key("secret-for-accept-test-xx")
    client = _make_client(symmetric_key=oct_key)
    auth = ClientSecretJWTAuth()
    result = auth(lambda cid: client, _make_request(alg="HS256", key=oct_key))
    assert result == client


def test_client_secret_jwt_skips_rs256():
    """client_secret_jwt handler returns None for RS256."""
    rsa_key = RSAKey.generate_key(2048)
    public_key = RSAKey.import_key(rsa_key.as_dict(private=False))
    client = _make_client(public_key=public_key)
    auth = ClientSecretJWTAuth()
    result = auth(lambda cid: client, _make_request(alg="RS256", key=rsa_key))
    assert result is None


def test_private_key_jwt_accepts_rs256():
    """private_key_jwt handler accepts and verifies RS256 assertion."""
    rsa_key = RSAKey.generate_key(2048)
    public_key = RSAKey.import_key(rsa_key.as_dict(private=False))
    client = _make_client(public_key=public_key)
    auth = PrivateKeyJWTAuth()
    result = auth(lambda cid: client, _make_request(alg="RS256", key=rsa_key))
    assert result == client


def test_private_key_jwt_skips_hs256():
    """private_key_jwt handler returns None for HS256."""
    oct_key = OctKey.import_key("secret-for-skip-test-xxx")
    client = _make_client(symmetric_key=oct_key)
    auth = PrivateKeyJWTAuth()
    result = auth(lambda cid: client, _make_request(alg="HS256", key=oct_key))
    assert result is None


def test_default_should_handle_accepts_all():
    """Base class should_handle returns True for any algorithm."""
    auth = JWTBearerClientAssertion()
    assert auth.should_handle({"alg": "HS256"}, {"sub": "c1"}) is True
    assert auth.should_handle({"alg": "RS256"}, {"sub": "c1"}) is True
    assert auth.should_handle({"alg": "ES256"}, {"sub": "c1"}) is True
