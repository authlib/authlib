import time
from types import SimpleNamespace
from unittest import mock

from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc7523 import PrivateKeyJWT
from tests.util import read_file_path

public_key = read_file_path("rsa_public.pem")
private_key = read_file_path("rsa_private.pem")


def test_nothing_set():
    jwt_signer = PrivateKeyJWT()

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims is None
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "RS256"


def test_endpoint_set():
    jwt_signer = PrivateKeyJWT(
        token_endpoint="https://provider.test/oauth/access_token"
    )

    assert jwt_signer.token_endpoint == "https://provider.test/oauth/access_token"
    assert jwt_signer.claims is None
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "RS256"


def test_alg_set():
    jwt_signer = PrivateKeyJWT(alg="RS512")

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims is None
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "RS512"


def test_claims_set():
    jwt_signer = PrivateKeyJWT(claims={"foo1": "bar1"})

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims == {"foo1": "bar1"}
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "RS256"


def test_headers_set():
    jwt_signer = PrivateKeyJWT(headers={"foo1": "bar1"})

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims is None
    assert jwt_signer.headers == {"foo1": "bar1"}
    assert jwt_signer.alg == "RS256"


def test_all_set():
    jwt_signer = PrivateKeyJWT(
        token_endpoint="https://provider.test/oauth/access_token",
        claims={"foo1a": "bar1a"},
        headers={"foo1b": "bar1b"},
        alg="RS512",
    )

    assert jwt_signer.token_endpoint == "https://provider.test/oauth/access_token"
    assert jwt_signer.claims == {"foo1a": "bar1a"}
    assert jwt_signer.headers == {"foo1b": "bar1b"}
    assert jwt_signer.alg == "RS512"


def sign_and_decode(jwt_signer, client_id, token_endpoint):
    auth = mock.MagicMock()
    auth.client_id = client_id
    auth.client_secret = private_key

    pre_sign_time = int(time.time())

    data = jwt_signer.sign(auth, token_endpoint)
    decoded = jwt.decode(data, RSAKey.import_key(public_key))

    iat = decoded.claims.pop("iat")
    exp = decoded.claims.pop("exp")
    jti = decoded.claims.pop("jti")

    return decoded, pre_sign_time, iat, exp, jti


def test_sign_nothing_set():
    jwt_signer = PrivateKeyJWT()

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat >= pre_sign_time
    assert exp >= iat + 3600
    assert exp <= iat + 3600 + 2
    assert jti is not None

    assert {
        "iss": "client_id_1",
        "aud": "https://provider.test/oauth/access_token",
        "sub": "client_id_1",
    } == decoded.claims
    assert {"alg": "RS256", "typ": "JWT"} == decoded.header


def test_sign_custom_jti():
    jwt_signer = PrivateKeyJWT(claims={"jti": "custom_jti"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat >= pre_sign_time
    assert exp >= iat + 3600
    assert exp <= iat + 3600 + 2
    assert "custom_jti" == jti

    assert decoded.claims == {
        "iss": "client_id_1",
        "aud": "https://provider.test/oauth/access_token",
        "sub": "client_id_1",
    }
    assert {"alg": "RS256", "typ": "JWT"} == decoded.header


def test_sign_with_additional_header():
    jwt_signer = PrivateKeyJWT(headers={"kid": "custom_kid"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat >= pre_sign_time
    assert exp >= iat + 3600
    assert exp <= iat + 3600 + 2
    assert jti is not None

    assert decoded.claims == {
        "iss": "client_id_1",
        "aud": "https://provider.test/oauth/access_token",
        "sub": "client_id_1",
    }
    assert {"alg": "RS256", "typ": "JWT", "kid": "custom_kid"} == decoded.header


def test_sign_with_additional_headers():
    jwt_signer = PrivateKeyJWT(
        headers={"kid": "custom_kid", "jku": "https://provider.test/oauth/jwks"}
    )

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat >= pre_sign_time
    assert exp >= iat + 3600
    assert exp <= iat + 3600 + 2
    assert jti is not None

    assert decoded.claims == {
        "iss": "client_id_1",
        "aud": "https://provider.test/oauth/access_token",
        "sub": "client_id_1",
    }
    assert {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "custom_kid",
        "jku": "https://provider.test/oauth/jwks",
    } == decoded.header


def test_sign_with_additional_claim():
    jwt_signer = PrivateKeyJWT(claims={"name": "Foo"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat >= pre_sign_time
    assert exp >= iat + 3600
    assert exp <= iat + 3600 + 2
    assert jti is not None

    assert decoded.claims == {
        "iss": "client_id_1",
        "aud": "https://provider.test/oauth/access_token",
        "sub": "client_id_1",
        "name": "Foo",
    }
    assert {"alg": "RS256", "typ": "JWT"} == decoded.header


def test_sign_with_additional_claims():
    jwt_signer = PrivateKeyJWT(claims={"name": "Foo", "role": "bar"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat >= pre_sign_time
    assert exp >= iat + 3600
    assert exp <= iat + 3600 + 2
    assert jti is not None

    assert decoded.claims == {
        "iss": "client_id_1",
        "aud": "https://provider.test/oauth/access_token",
        "sub": "client_id_1",
        "name": "Foo",
        "role": "bar",
    }
    assert {"alg": "RS256", "typ": "JWT"} == decoded.header


def test_sign_with_ec_key():
    """``PrivateKeyJWT`` should accept an ``ECKey`` private key and sign with ES256."""
    ec_key = ECKey.generate_key("P-256", private=True)
    jwt_signer = PrivateKeyJWT(alg="ES256")
    auth = SimpleNamespace(client_id="client_id_1", client_secret=ec_key)

    data = jwt_signer.sign(auth, "https://provider.test/oauth/access_token")
    decoded = jwt.decode(data, ec_key)

    assert decoded.claims["iss"] == "client_id_1"
    assert decoded.claims["sub"] == "client_id_1"
    assert decoded.claims["aud"] == "https://provider.test/oauth/access_token"
    assert decoded.header["alg"] == "ES256"


def test_sign_with_non_recommended_alg():
    """Signing must work with algorithms outside joserfc's recommended set."""
    jwt_signer = PrivateKeyJWT(alg="RS384")

    auth = mock.MagicMock()
    auth.client_id = "client_id_1"
    auth.client_secret = private_key

    data = jwt_signer.sign(auth, "https://provider.test/oauth/access_token")
    decoded = jwt.decode(data, RSAKey.import_key(public_key), algorithms=["RS384"])

    assert decoded.header["alg"] == "RS384"


def test_sign_with_custom_issued_at_and_expires_in():
    fixed_iat = 123456789
    jwt_signer = PrivateKeyJWT(issued_at=fixed_iat, expires_in=123)

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "https://provider.test/oauth/access_token",
    )

    assert iat == fixed_iat
    assert exp == fixed_iat + 123
