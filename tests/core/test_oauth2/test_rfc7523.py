import time
from unittest import TestCase
from unittest import mock

from authlib.jose import jwt
from authlib.oauth2.rfc7523 import ClientSecretJWT
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from tests.util import read_file_path


class ClientSecretJWTTest(TestCase):
    def test_nothing_set(self):
        jwt_signer = ClientSecretJWT()

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims is None
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "HS256"

    def test_endpoint_set(self):
        jwt_signer = ClientSecretJWT(
            token_endpoint="https://example.com/oauth/access_token"
        )

        assert jwt_signer.token_endpoint == "https://example.com/oauth/access_token"
        assert jwt_signer.claims is None
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "HS256"

    def test_alg_set(self):
        jwt_signer = ClientSecretJWT(alg="HS512")

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims is None
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "HS512"

    def test_claims_set(self):
        jwt_signer = ClientSecretJWT(claims={"foo1": "bar1"})

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims == {"foo1": "bar1"}
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "HS256"

    def test_headers_set(self):
        jwt_signer = ClientSecretJWT(headers={"foo1": "bar1"})

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims is None
        assert jwt_signer.headers == {"foo1": "bar1"}
        assert jwt_signer.alg == "HS256"

    def test_all_set(self):
        jwt_signer = ClientSecretJWT(
            token_endpoint="https://example.com/oauth/access_token",
            claims={"foo1a": "bar1a"},
            headers={"foo1b": "bar1b"},
            alg="HS512",
        )

        assert jwt_signer.token_endpoint == "https://example.com/oauth/access_token"
        assert jwt_signer.claims == {"foo1a": "bar1a"}
        assert jwt_signer.headers == {"foo1b": "bar1b"}
        assert jwt_signer.alg == "HS512"

    @staticmethod
    def sign_and_decode(jwt_signer, client_id, client_secret, token_endpoint):
        auth = mock.MagicMock()
        auth.client_id = client_id
        auth.client_secret = client_secret

        pre_sign_time = int(time.time())

        data = jwt_signer.sign(auth, token_endpoint).decode("utf-8")
        decoded = jwt.decode(
            data, client_secret
        )  # , claims_cls=None, claims_options=None, claims_params=None):

        iat = decoded.pop("iat")
        exp = decoded.pop("exp")
        jti = decoded.pop("jti")

        return decoded, pre_sign_time, iat, exp, jti

    def test_sign_nothing_set(self):
        jwt_signer = ClientSecretJWT()

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            "client_secret_1",
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        } == decoded

        assert {"alg": "HS256", "typ": "JWT"} == decoded.header

    def test_sign_custom_jti(self):
        jwt_signer = ClientSecretJWT(claims={"jti": "custom_jti"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            "client_secret_1",
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert "custom_jti" == jti

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        }
        assert {"alg": "HS256", "typ": "JWT"} == decoded.header

    def test_sign_with_additional_header(self):
        jwt_signer = ClientSecretJWT(headers={"kid": "custom_kid"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            "client_secret_1",
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        }
        assert {"alg": "HS256", "typ": "JWT", "kid": "custom_kid"} == decoded.header

    def test_sign_with_additional_headers(self):
        jwt_signer = ClientSecretJWT(
            headers={"kid": "custom_kid", "jku": "https://example.com/oauth/jwks"}
        )

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            "client_secret_1",
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        }
        assert {
            "alg": "HS256",
            "typ": "JWT",
            "kid": "custom_kid",
            "jku": "https://example.com/oauth/jwks",
        } == decoded.header

    def test_sign_with_additional_claim(self):
        jwt_signer = ClientSecretJWT(claims={"name": "Foo"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            "client_secret_1",
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
            "name": "Foo",
        }
        assert {"alg": "HS256", "typ": "JWT"} == decoded.header

    def test_sign_with_additional_claims(self):
        jwt_signer = ClientSecretJWT(claims={"name": "Foo", "role": "bar"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            "client_secret_1",
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
            "name": "Foo",
            "role": "bar",
        }
        assert {"alg": "HS256", "typ": "JWT"} == decoded.header


class PrivateKeyJWTTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key = read_file_path("rsa_public.pem")
        cls.private_key = read_file_path("rsa_private.pem")

    def test_nothing_set(self):
        jwt_signer = PrivateKeyJWT()

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims is None
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "RS256"

    def test_endpoint_set(self):
        jwt_signer = PrivateKeyJWT(
            token_endpoint="https://example.com/oauth/access_token"
        )

        assert jwt_signer.token_endpoint == "https://example.com/oauth/access_token"
        assert jwt_signer.claims is None
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "RS256"

    def test_alg_set(self):
        jwt_signer = PrivateKeyJWT(alg="RS512")

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims is None
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "RS512"

    def test_claims_set(self):
        jwt_signer = PrivateKeyJWT(claims={"foo1": "bar1"})

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims == {"foo1": "bar1"}
        assert jwt_signer.headers is None
        assert jwt_signer.alg == "RS256"

    def test_headers_set(self):
        jwt_signer = PrivateKeyJWT(headers={"foo1": "bar1"})

        assert jwt_signer.token_endpoint is None
        assert jwt_signer.claims is None
        assert jwt_signer.headers == {"foo1": "bar1"}
        assert jwt_signer.alg == "RS256"

    def test_all_set(self):
        jwt_signer = PrivateKeyJWT(
            token_endpoint="https://example.com/oauth/access_token",
            claims={"foo1a": "bar1a"},
            headers={"foo1b": "bar1b"},
            alg="RS512",
        )

        assert jwt_signer.token_endpoint == "https://example.com/oauth/access_token"
        assert jwt_signer.claims == {"foo1a": "bar1a"}
        assert jwt_signer.headers == {"foo1b": "bar1b"}
        assert jwt_signer.alg == "RS512"

    @staticmethod
    def sign_and_decode(jwt_signer, client_id, public_key, private_key, token_endpoint):
        auth = mock.MagicMock()
        auth.client_id = client_id
        auth.client_secret = private_key

        pre_sign_time = int(time.time())

        data = jwt_signer.sign(auth, token_endpoint).decode("utf-8")
        decoded = jwt.decode(
            data, public_key
        )  # , claims_cls=None, claims_options=None, claims_params=None):

        iat = decoded.pop("iat")
        exp = decoded.pop("exp")
        jti = decoded.pop("jti")

        return decoded, pre_sign_time, iat, exp, jti

    def test_sign_nothing_set(self):
        jwt_signer = PrivateKeyJWT()

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            self.public_key,
            self.private_key,
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        } == decoded
        assert {"alg": "RS256", "typ": "JWT"} == decoded.header

    def test_sign_custom_jti(self):
        jwt_signer = PrivateKeyJWT(claims={"jti": "custom_jti"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            self.public_key,
            self.private_key,
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert "custom_jti" == jti

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        }
        assert {"alg": "RS256", "typ": "JWT"} == decoded.header

    def test_sign_with_additional_header(self):
        jwt_signer = PrivateKeyJWT(headers={"kid": "custom_kid"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            self.public_key,
            self.private_key,
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        }
        assert {"alg": "RS256", "typ": "JWT", "kid": "custom_kid"} == decoded.header

    def test_sign_with_additional_headers(self):
        jwt_signer = PrivateKeyJWT(
            headers={"kid": "custom_kid", "jku": "https://example.com/oauth/jwks"}
        )

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            self.public_key,
            self.private_key,
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
        }
        assert {
            "alg": "RS256",
            "typ": "JWT",
            "kid": "custom_kid",
            "jku": "https://example.com/oauth/jwks",
        } == decoded.header

    def test_sign_with_additional_claim(self):
        jwt_signer = PrivateKeyJWT(claims={"name": "Foo"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            self.public_key,
            self.private_key,
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
            "name": "Foo",
        }
        assert {"alg": "RS256", "typ": "JWT"} == decoded.header

    def test_sign_with_additional_claims(self):
        jwt_signer = PrivateKeyJWT(claims={"name": "Foo", "role": "bar"})

        decoded, pre_sign_time, iat, exp, jti = self.sign_and_decode(
            jwt_signer,
            "client_id_1",
            self.public_key,
            self.private_key,
            "https://example.com/oauth/access_token",
        )

        assert iat >= pre_sign_time
        assert exp >= iat + 3600
        assert exp <= iat + 3600 + 2
        assert jti is not None

        assert decoded == {
            "iss": "client_id_1",
            "aud": "https://example.com/oauth/access_token",
            "sub": "client_id_1",
            "name": "Foo",
            "role": "bar",
        }
        assert {"alg": "RS256", "typ": "JWT"} == decoded.header
