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


def test_custom_leeway(oct_key):
    claims = {
        "exp": int(time.time()) - 30,
        "client_id": "client-id",
        "grant_type": "client_credentials",
    }
    token_string = jwt.encode({"alg": "HS256"}, claims, oct_key)

    validator_no_leeway = JWTBearerTokenValidator(oct_key, leeway=0)
    token = validator_no_leeway.authenticate_token(token_string)
    assert token is None

    validator_with_leeway = JWTBearerTokenValidator(oct_key, leeway=60)
    token = validator_with_leeway.authenticate_token(token_string)
    assert token is not None


@pytest.fixture
def claims():
    return {
        "exp": int(time.time() + 3600),
        "client_id": "client-id",
        "grant_type": "client_credentials",
    }


def test_audience(oct_key, claims):
    """A token is accepted when its aud contains the configured audience."""
    validator = JWTBearerTokenValidator(oct_key, audience="https://rs-a.example")
    for aud in (
        "https://rs-a.example",
        ["https://rs-b.example", "https://rs-a.example"],
    ):
        token_string = jwt.encode({"alg": "HS256"}, {**claims, "aud": aud}, oct_key)
        assert validator.authenticate_token(token_string) is not None


def test_audience_mismatch(oct_key, claims):
    """A token issued for another resource server is rejected."""
    validator = JWTBearerTokenValidator(oct_key, audience="https://rs-b.example")
    token_string = jwt.encode(
        {"alg": "HS256"}, {**claims, "aud": "https://rs-a.example"}, oct_key
    )
    assert validator.authenticate_token(token_string) is None


def test_audience_missing(oct_key, claims):
    """A token without aud is rejected when an audience is configured."""
    validator = JWTBearerTokenValidator(oct_key, audience="https://rs-a.example")
    token_string = jwt.encode({"alg": "HS256"}, claims, oct_key)
    assert validator.authenticate_token(token_string) is None


@pytest.mark.parametrize("aud", ["https://rs-a.example", [], ""])
def test_unexpected_audience(oct_key, claims, aud):
    """A token with aud is rejected when no audience is configured."""
    validator = JWTBearerTokenValidator(oct_key)
    token_string = jwt.encode({"alg": "HS256"}, {**claims, "aud": aud}, oct_key)
    assert validator.authenticate_token(token_string) is None


def test_no_audience(oct_key, claims):
    """A token without aud is accepted when no audience is configured."""
    validator = JWTBearerTokenValidator(oct_key)
    token_string = jwt.encode({"alg": "HS256"}, claims, oct_key)
    assert validator.authenticate_token(token_string) is not None


def test_custom_audience_claims_option(oct_key, claims):
    """An aud check added to claims_options is kept."""
    validator = JWTBearerTokenValidator(oct_key)
    validator.claims_options["aud"] = {
        "essential": True,
        "value": "https://rs-a.example",
    }
    token_string = jwt.encode(
        {"alg": "HS256"}, {**claims, "aud": "https://rs-a.example"}, oct_key
    )
    assert validator.authenticate_token(token_string) is not None
