"""Tests for automatic propagation of kid and alg from JWK to JWT header.

When a key already carries kid and/or alg metadata, the assertion signing
functions should copy them into the JWT header automatically so callers
don't have to repeat what is already in the key.
"""

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey
from joserfc.jwk import OKPKey

from authlib.oauth2.rfc7523.assertion import client_secret_jwt_sign
from authlib.oauth2.rfc7523.assertion import private_key_jwt_sign
from authlib.oauth2.rfc7523.assertion import set_jwt_header_parameter_from_key
from authlib.oauth2.rfc7523.assertion import sign_jwt_bearer_assertion

CLIENT_ID = "test-client"
TOKEN_ENDPOINT = "https://auth.example.com/token"


# -- set_jwt_header_parameter_from_key ---------------------------------------


def test_set_header_param_copies_from_key():
    key = OctKey.generate_key(384, parameters={"alg": "HS384", "kid": "k1"})
    header: dict = {}

    set_jwt_header_parameter_from_key(header, key, "alg")
    set_jwt_header_parameter_from_key(header, key, "kid")

    assert header == {"alg": "HS384", "kid": "k1"}


def test_set_header_param_overwrites_existing_value():
    """Key's value is an enforced constraint and must take priority."""
    key = OctKey.generate_key(384, parameters={"alg": "HS384"})
    header = {"alg": "HS512"}

    set_jwt_header_parameter_from_key(header, key, "alg")

    assert header["alg"] == "HS384"


def test_set_header_param_noop_when_key_lacks_param():
    key = OctKey.generate_key(256)
    header = {"alg": "HS384"}

    set_jwt_header_parameter_from_key(header, key, "kid")

    assert "kid" not in header


def test_set_header_param_noop_for_non_base_key():
    header: dict = {}

    set_jwt_header_parameter_from_key(header, "raw-secret", "alg")

    assert header == {}


# -- sign_jwt_bearer_assertion — alg priority --------------------------------


def test_alg_resolved_from_key_when_no_explicit_alg():
    key = OctKey.generate_key(384, parameters={"alg": "HS384"})

    token = sign_jwt_bearer_assertion(
        key=key, issuer=CLIENT_ID, audience=TOKEN_ENDPOINT
    )

    decoded = jwt.decode(token, key, algorithms=["HS384"])
    assert decoded.header["alg"] == "HS384"


def test_key_alg_overwrites_explicit_alg():
    key = OctKey.generate_key(384, parameters={"alg": "HS384"})

    token = sign_jwt_bearer_assertion(
        key=key, issuer=CLIENT_ID, audience=TOKEN_ENDPOINT, alg="HS512"
    )

    decoded = jwt.decode(token, key, algorithms=["HS384"])
    assert decoded.header["alg"] == "HS384"


def test_raises_when_no_alg_available():
    key = OctKey.generate_key(256)

    with pytest.raises(ValueError, match="Missing 'alg'"):
        sign_jwt_bearer_assertion(key=key, issuer=CLIENT_ID, audience=TOKEN_ENDPOINT)


# -- sign_jwt_bearer_assertion — kid propagation -----------------------------


def test_kid_propagated_from_key():
    key = OctKey.generate_key(384, parameters={"alg": "HS384", "kid": "oct-1"})

    token = sign_jwt_bearer_assertion(
        key=key, issuer=CLIENT_ID, audience=TOKEN_ENDPOINT
    )

    decoded = jwt.decode(token, key, algorithms=["HS384"])
    assert decoded.header["kid"] == "oct-1"


def test_no_kid_when_key_has_none():
    key = OctKey.generate_key(384, parameters={"alg": "HS384"})

    token = sign_jwt_bearer_assertion(
        key=key, issuer=CLIENT_ID, audience=TOKEN_ENDPOINT
    )

    decoded = jwt.decode(token, key, algorithms=["HS384"])
    assert "kid" not in decoded.header


# -- client_secret_jwt_sign — auto-propagation -------------------------------


def test_client_secret_jwt_propagates_alg_and_kid():
    """Key's HS384 overrides the default HS256; kid is also propagated."""
    key = OctKey.generate_key(384, parameters={"alg": "HS384", "kid": "hmac-1"})

    token = client_secret_jwt_sign(
        client_secret=key, client_id=CLIENT_ID, token_endpoint=TOKEN_ENDPOINT
    )

    decoded = jwt.decode(token, key, algorithms=["HS384"])
    assert decoded.header["alg"] == "HS384"
    assert decoded.header["kid"] == "hmac-1"


# -- private_key_jwt_sign — auto-propagation ---------------------------------


def test_private_key_jwt_propagates_ed25519():
    """Ed25519 key's EdDSA alg overrides the default RS256; kid propagated."""
    key = OKPKey.generate_key(
        crv="Ed25519", private=True, parameters={"alg": "Ed25519", "kid": "ed-1"}
    )

    token = private_key_jwt_sign(
        private_key=key, client_id=CLIENT_ID, token_endpoint=TOKEN_ENDPOINT
    )

    decoded = jwt.decode(token, key, algorithms=["Ed25519"])
    assert decoded.header["alg"] == "Ed25519"
    assert decoded.header["kid"] == "ed-1"
    assert decoded.claims["iss"] == CLIENT_ID
    assert decoded.claims["sub"] == CLIENT_ID
    assert decoded.claims["aud"] == TOKEN_ENDPOINT


def test_private_key_jwt_propagates_ec_p256():
    key = ECKey.generate_key(
        crv="P-256", private=True, parameters={"alg": "ES256", "kid": "ec-1"}
    )

    token = private_key_jwt_sign(
        private_key=key, client_id=CLIENT_ID, token_endpoint=TOKEN_ENDPOINT
    )

    decoded = jwt.decode(token, key, algorithms=["ES256"])
    assert decoded.header["alg"] == "ES256"
    assert decoded.header["kid"] == "ec-1"
