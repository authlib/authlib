import pytest
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc7523.assertion import sign_jwt_bearer_assertion
from tests.util import HMAC_SECRET

hmac_key = OctKey.import_key(HMAC_SECRET)


def decode(token):
    return jwt.decode(token, hmac_key).claims


def test_default_jti_is_generated():
    token = sign_jwt_bearer_assertion(
        key=hmac_key,
        issuer="client1",
        audience="https://auth.example/token",
        alg="HS256",
    )
    claims = decode(token)
    assert "jti" in claims
    assert len(claims["jti"]) == 36


def test_custom_jti_is_preserved():
    token = sign_jwt_bearer_assertion(
        key=hmac_key,
        issuer="client1",
        audience="https://auth.example/token",
        alg="HS256",
        claims={"jti": "my-custom-jti"},
    )
    claims = decode(token)
    assert claims["jti"] == "my-custom-jti"


def test_each_call_generates_unique_jti():
    tokens = [
        sign_jwt_bearer_assertion(
            key=hmac_key,
            issuer="client1",
            audience="https://auth.example/token",
            alg="HS256",
        )
        for _ in range(5)
    ]
    jtis = [decode(t)["jti"] for t in tokens]
    assert all(jtis)
    assert len(set(jtis)) == 5


def test_claims_with_other_fields_still_gets_jti():
    token = sign_jwt_bearer_assertion(
        key=hmac_key,
        issuer="client1",
        audience="https://auth.example/token",
        alg="HS256",
        claims={"custom_field": "value"},
    )
    claims = decode(token)
    assert claims["jti"]
    assert claims["custom_field"] == "value"


@pytest.mark.filterwarnings(
    "ignore:Using implicit key type:joserfc.errors.SecurityWarning"
)
def test_raw_string_key_is_deprecated():
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        token = sign_jwt_bearer_assertion(
            key=HMAC_SECRET,
            issuer="client1",
            audience="https://auth.example/token",
            alg="HS256",
        )
    assert decode(token)["iss"] == "client1"
