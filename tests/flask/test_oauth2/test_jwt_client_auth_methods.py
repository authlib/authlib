import pytest
from flask import json
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc7523 import ClientSecretJWTAuthentication
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7523 import PrivateKeyJWTAuthentication
from authlib.oauth2.rfc7523 import client_secret_jwt_sign
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from tests.util import HMAC_SECRET

TOKEN_ENDPOINT = "https://provider.test/oauth/token"
secret_key = OctKey.import_key(HMAC_SECRET)
rsa_key = RSAKey.generate_key(2048, private=True)


class _Audiences:
    def get_audiences(self):
        return [TOKEN_ENDPOINT]

    def validate_jti(self, claims, jti):
        return True


class SecretAuth(_Audiences, ClientSecretJWTAuthentication):
    def resolve_client_secret(self, client):
        return client.client_secret


class KeyAuth(_Audiences, PrivateKeyJWTAuthentication):
    public_key = rsa_key

    def resolve_client_public_key(self, client):
        return self.public_key


@pytest.fixture(autouse=True)
def server(server):
    class Grant(ClientCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_jwt", "private_key_jwt"]

    server.register_grant(Grant)
    server.register_client_auth_method("client_secret_jwt", SecretAuth())
    server.register_client_auth_method("private_key_jwt", KeyAuth())
    return server


def set_auth_method(client, db, method):
    client.client_secret = HMAC_SECRET
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": method,
        }
    )
    db.session.add(client)
    db.session.commit()


def request_token(test_client, assertion):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        },
    )
    return json.loads(rv.data)


def sign_with_secret(alg="HS256"):
    return client_secret_jwt_sign(
        secret_key, client_id="client-id", token_endpoint=TOKEN_ENDPOINT, alg=alg
    )


def sign_with_key(key=rsa_key, alg="RS256"):
    return private_key_jwt_sign(
        key, client_id="client-id", token_endpoint=TOKEN_ENDPOINT, alg=alg
    )


@pytest.mark.parametrize("alg", ["HS256", "HS512"])
def test_client_secret_jwt(test_client, client, db, alg):
    """A client_secret_jwt client authenticates with its secret."""
    set_auth_method(client, db, "client_secret_jwt")
    assert "access_token" in request_token(test_client, sign_with_secret(alg))


def test_client_secret_jwt_with_private_key(test_client, client, db):
    """A client_secret_jwt client cannot authenticate with a private key."""
    set_auth_method(client, db, "client_secret_jwt")
    resp = request_token(test_client, sign_with_key())
    assert resp["error"] == "invalid_client"


@pytest.mark.parametrize(
    "key,alg",
    [
        (rsa_key, "RS256"),
        (rsa_key, "PS256"),
        (ECKey.generate_key("P-384", private=True), "ES384"),
        (OKPKey.generate_key("Ed25519", private=True), "Ed25519"),
    ],
)
def test_private_key_jwt(test_client, client, db, monkeypatch, key, alg):
    """A private_key_jwt client authenticates with its private key."""
    set_auth_method(client, db, "private_key_jwt")
    monkeypatch.setattr(KeyAuth, "public_key", key)
    assert "access_token" in request_token(test_client, sign_with_key(key, alg))


def test_private_key_jwt_with_secret(test_client, client, db):
    """A private_key_jwt client cannot authenticate with its secret."""
    set_auth_method(client, db, "private_key_jwt")
    resp = request_token(test_client, sign_with_secret())
    assert resp["error"] == "invalid_client"


def test_private_key_jwt_with_symmetric_key_in_jwks(
    test_client, client, db, monkeypatch
):
    """An oct key in the client JWK set cannot verify private_key_jwt assertions."""
    set_auth_method(client, db, "private_key_jwt")
    oct_key = OctKey.import_key(HMAC_SECRET, {"kid": "sym"})
    monkeypatch.setattr(KeyAuth, "public_key", KeySet([rsa_key, oct_key]))
    assertion = jwt.encode(
        {"alg": "HS256", "kid": "sym"},
        {
            "iss": "client-id",
            "sub": "client-id",
            "aud": TOKEN_ENDPOINT,
            "exp": 9999999999,
            "jti": "jti",
        },
        oct_key,
    )
    resp = request_token(test_client, assertion)
    assert resp["error"] == "invalid_client"


def test_other_auth_method(test_client, client, db):
    """A client registered with another method cannot use JWT assertions."""
    set_auth_method(client, db, "client_secret_basic")
    resp = request_token(test_client, sign_with_secret())
    assert resp["error"] == "invalid_client"


def test_client_assertion_jwt_is_deprecated():
    """Using or subclassing JWTBearerClientAssertion is deprecated."""
    with pytest.warns(AuthlibDeprecationWarning, match="JWTBearerClientAssertion"):
        JWTBearerClientAssertion()

    class OldAuth(JWTBearerClientAssertion):
        CLIENT_AUTH_METHOD = "private_key_jwt"

    with pytest.warns(AuthlibDeprecationWarning, match="JWTBearerClientAssertion"):
        OldAuth()


@pytest.mark.parametrize("secret", [None, ""])
def test_client_secret_jwt_without_secret(test_client, client, db, secret):
    """A client_secret_jwt client without a secret gets invalid_client."""
    set_auth_method(client, db, "client_secret_jwt")
    client.client_secret = secret
    db.session.add(client)
    db.session.commit()
    resp = request_token(test_client, sign_with_secret())
    assert resp["error"] == "invalid_client"


def test_new_methods_are_not_deprecated(recwarn):
    """The client_secret_jwt and private_key_jwt classes do not warn."""
    SecretAuth()
    KeyAuth()
    assert not [w for w in recwarn if w.category is AuthlibDeprecationWarning]
