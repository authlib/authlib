import time

import pytest
from joserfc import jws
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc7523 import JWTBearerTokenValidator


@pytest.fixture
def oct_key():
    return OctKey.generate_key()


def test_invalid_token_string(oct_key):
    validator = JWTBearerTokenValidator(oct_key)
    token_string = jws.serialize_compact({"alg": "HS256"}, "text", oct_key)
    token = validator.authenticate_token(token_string)
    assert token is None


def test_missint_claims(oct_key):
    validator = JWTBearerTokenValidator(oct_key)
    token_string = jwt.encode({"alg": "HS256"}, {}, oct_key)
    token = validator.authenticate_token(token_string)
    assert token is None


def test_authenticate_token(oct_key):
    validator = JWTBearerTokenValidator(oct_key, issuer="foo")
    claims = {
        "iss": "bar",
        "exp": int(time.time() + 3600),
        "client_id": "client-id",
        "grant_type": "client_credentials",
    }
    token_string = jwt.encode({"alg": "HS256"}, claims, oct_key)
    token = validator.authenticate_token(token_string)
    assert token is None

    token_string = jwt.encode({"alg": "HS256"}, {**claims, "iss": "foo"}, oct_key)
    token = validator.authenticate_token(token_string)
    assert token is not None


def test_expired_token(oct_key):
    validator = JWTBearerTokenValidator(oct_key)
    claims = {
        "exp": time.time() + 0.01,
        "client_id": "client-id",
        "grant_type": "client_credentials",
    }
    token_string = jwt.encode({"alg": "HS256"}, claims, oct_key)
    token = validator.authenticate_token(token_string)
    assert token is not None

    time.sleep(0.1)
    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, [], None)
