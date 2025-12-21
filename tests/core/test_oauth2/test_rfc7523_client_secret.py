import time
from unittest import mock

from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.oauth2.rfc7523 import ClientSecretJWT


def test_nothing_set():
    jwt_signer = ClientSecretJWT()

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims is None
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "HS256"


def test_endpoint_set():
    jwt_signer = ClientSecretJWT(
        token_endpoint="https://provider.test/oauth/access_token"
    )

    assert jwt_signer.token_endpoint == "https://provider.test/oauth/access_token"
    assert jwt_signer.claims is None
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "HS256"


def test_alg_set():
    jwt_signer = ClientSecretJWT(alg="HS512")

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims is None
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "HS512"


def test_claims_set():
    jwt_signer = ClientSecretJWT(claims={"foo1": "bar1"})

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims == {"foo1": "bar1"}
    assert jwt_signer.headers is None
    assert jwt_signer.alg == "HS256"


def test_headers_set():
    jwt_signer = ClientSecretJWT(headers={"foo1": "bar1"})

    assert jwt_signer.token_endpoint is None
    assert jwt_signer.claims is None
    assert jwt_signer.headers == {"foo1": "bar1"}
    assert jwt_signer.alg == "HS256"


def test_all_set():
    jwt_signer = ClientSecretJWT(
        token_endpoint="https://provider.test/oauth/access_token",
        claims={"foo1a": "bar1a"},
        headers={"foo1b": "bar1b"},
        alg="HS512",
    )

    assert jwt_signer.token_endpoint == "https://provider.test/oauth/access_token"
    assert jwt_signer.claims == {"foo1a": "bar1a"}
    assert jwt_signer.headers == {"foo1b": "bar1b"}
    assert jwt_signer.alg == "HS512"


def sign_and_decode(jwt_signer, client_id, client_secret, token_endpoint):
    auth = mock.MagicMock()
    auth.client_id = client_id
    auth.client_secret = client_secret

    pre_sign_time = int(time.time())

    data = jwt_signer.sign(auth, token_endpoint)
    decoded = jwt.decode(data, OctKey.import_key(client_secret))

    iat = decoded.claims.pop("iat")
    exp = decoded.claims.pop("exp")
    jti = decoded.claims.pop("jti")

    return decoded, pre_sign_time, iat, exp, jti


def test_sign_nothing_set():
    jwt_signer = ClientSecretJWT()

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "client_secret_1",
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

    assert {"alg": "HS256", "typ": "JWT"} == decoded.header


def test_sign_custom_jti():
    jwt_signer = ClientSecretJWT(claims={"jti": "custom_jti"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "client_secret_1",
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
    assert {"alg": "HS256", "typ": "JWT"} == decoded.header


def test_sign_with_additional_header():
    jwt_signer = ClientSecretJWT(headers={"kid": "custom_kid"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "client_secret_1",
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
    assert {"alg": "HS256", "typ": "JWT", "kid": "custom_kid"} == decoded.header


def test_sign_with_additional_headers():
    jwt_signer = ClientSecretJWT(
        headers={"kid": "custom_kid", "jku": "https://provider.test/oauth/jwks"}
    )

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "client_secret_1",
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
        "alg": "HS256",
        "typ": "JWT",
        "kid": "custom_kid",
        "jku": "https://provider.test/oauth/jwks",
    } == decoded.header


def test_sign_with_additional_claim():
    jwt_signer = ClientSecretJWT(claims={"name": "Foo"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "client_secret_1",
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
    assert {"alg": "HS256", "typ": "JWT"} == decoded.header


def test_sign_with_additional_claims():
    jwt_signer = ClientSecretJWT(claims={"name": "Foo", "role": "bar"})

    decoded, pre_sign_time, iat, exp, jti = sign_and_decode(
        jwt_signer,
        "client_id_1",
        "client_secret_1",
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
    assert {"alg": "HS256", "typ": "JWT"} == decoded.header
