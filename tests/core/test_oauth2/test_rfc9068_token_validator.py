"""Tests for RFC 9068 JWTBearerTokenValidator.authenticate_token.

Verifies that all joserfc errors raised during JWT decoding — including
InvalidKeyIdError — are converted to authlib's InvalidTokenError.
"""

import time

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator

ISSUER = "https://auth.example.com"
RESOURCE_SERVER = "https://api.example.com"


def _make_validator(key):
    class Validator(JWTBearerTokenValidator):
        def get_jwks(self):
            return key

    return Validator(issuer=ISSUER, resource_server=RESOURCE_SERVER)


def _encode_token(key, claims=None):
    base_claims = {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": "unique-jti",
    }
    if claims:
        base_claims.update(claims)
    return jwt.encode({"alg": "HS256"}, base_claims, key)


def test_valid_token():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key)
    token = validator.authenticate_token(token_string)

    assert token is not None
    assert token["sub"] == "user-1"


def test_invalid_signature_raises_invalid_token_error():
    signing_key = OctKey.generate_key()
    wrong_key = OctKey.generate_key()
    validator = _make_validator(wrong_key)

    token_string = _encode_token(signing_key)

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_mismatched_kid_raises_invalid_token_error():
    """InvalidKeyIdError (not a subclass of DecodeError) must be caught."""
    key = RSAKey.generate_key(2048, private=True, parameters={"kid": "key-1"})
    key_set = KeySet(keys=[key])
    validator = _make_validator(key_set)

    # Encode a token with a kid that doesn't exist in the key set
    other_key = RSAKey.generate_key(2048, private=True, parameters={"kid": "key-999"})
    token_string = jwt.encode(
        {"alg": "RS256", "kid": "key-999"},
        {
            "iss": ISSUER,
            "aud": RESOURCE_SERVER,
            "sub": "user-1",
            "client_id": "client-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": "unique-jti",
        },
        other_key,
    )

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_garbage_token_raises_invalid_token_error():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token("not.a.jwt")
