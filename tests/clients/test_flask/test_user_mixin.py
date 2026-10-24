import time
from unittest import mock

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.errors import BadSignatureError
from joserfc.errors import ExpiredTokenError
from joserfc.errors import InvalidClaimError
from joserfc.errors import JoseError
from joserfc.errors import MissingClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib.common.errors import AuthlibBaseError
from authlib.integrations.base_client import InvalidIDTokenError
from authlib.integrations.base_client import OAuthError
from authlib.integrations.base_client.errors import wrap_id_token_error
from authlib.integrations.flask_client import OAuth
from authlib.oidc.core.grants.util import create_half_hash

from ..util import get_bearer_token
from ..util import read_key_file

secret_key = OctKey.import_key("test-oct-secret", {"kty": "oct", "kid": "f"})


def test_fetch_userinfo():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        userinfo_endpoint="https://provider.test/userinfo",
    )

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: {"sub": "123"}
        resp.status_code = 200
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user.sub == "123"


def test_parse_id_token():
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": "n",
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256"}, claims, secret_key)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256", "RS256"],
    )
    with app.test_request_context():
        assert client.parse_id_token(token, nonce="n") is None

        token["id_token"] = id_token
        user = client.parse_id_token(token, nonce="n")
        assert user.sub == "123"

        claims_options = {"iss": {"value": "https://provider.test"}}
        user = client.parse_id_token(token, nonce="n", claims_options=claims_options)
        assert user.sub == "123"

        claims_options = {"iss": {"value": "https://wrong-provider.test"}}
        with pytest.raises(InvalidClaimError):
            client.parse_id_token(token, "n", claims_options)


@pytest.mark.parametrize("token_nonce", [None, "wrong", "n"])
def test_parse_id_token_nonce_supported(token_nonce):
    token = get_bearer_token()

    now = int(time.time())
    claims = {
        "sub": "123",
        "nonce_supported": False,
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    if token_nonce is not None:
        claims["nonce"] = token_nonce
    id_token = jwt.encode({"alg": "HS256"}, claims, secret_key)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256", "RS256"],
    )
    with app.test_request_context():
        token["id_token"] = id_token
        if token_nonce == "n":
            assert client.parse_id_token(token, nonce="n").sub == "123"
        else:
            error = MissingClaimError if token_nonce is None else InvalidClaimError
            with pytest.raises(error):
                client.parse_id_token(token, nonce="n")

        # Only the application can explicitly omit the expected nonce.
        assert client.parse_id_token(token, nonce=None).sub == "123"


def test_runtime_error_fetch_jwks_uri():
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "nonce": "n",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256", "kid": "not-found"}, claims, secret_key)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    alt_key = secret_key.as_dict()
    alt_key["kid"] = "b"
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [alt_key]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256"],
    )
    with app.test_request_context():
        token["id_token"] = id_token
        with pytest.raises(RuntimeError):
            client.parse_id_token(token, "n")


def test_force_fetch_jwks_uri():
    secret_keys = KeySet.import_key_set(read_key_file("jwks_private.json"))
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "nonce": "n",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "RS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "RS256"}, claims, secret_keys)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        jwks_uri="https://provider.test/jwks",
        issuer="https://provider.test",
    )

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: read_key_file("jwks_public.json")
        resp.status_code = 200
        return resp

    with app.test_request_context():
        assert client.parse_id_token(token, nonce="n") is None

        with mock.patch("requests.sessions.Session.send", fake_send):
            token["id_token"] = id_token
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "123"


def _encode_invalid_id_token(case, token):
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": "n",
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    key = secret_key
    if case == "expired":
        claims["iat"] = now - 7200
        claims["exp"] = now - 3600
    elif case == "wrong_issuer":
        claims["iss"] = "https://wrong-provider.test"
    elif case == "wrong_nonce":
        claims["nonce"] = "wrong"
    elif case == "bad_signature":
        key = OctKey.import_key("another-oct-secret", {"kty": "oct", "kid": "f"})
    return jwt.encode({"alg": "HS256"}, claims, key)


@pytest.mark.parametrize(
    "case,jose_error",
    [
        ("expired", ExpiredTokenError),
        ("wrong_issuer", InvalidClaimError),
        ("wrong_nonce", InvalidClaimError),
        ("bad_signature", BadSignatureError),
    ],
)
def test_parse_id_token_errors_are_authlib_errors(case, jose_error):
    """ID token failures are AuthlibBaseError subclasses (issue #966)."""
    token = get_bearer_token()
    token["id_token"] = _encode_invalid_id_token(case, token)

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256", "RS256"],
    )
    with app.test_request_context():
        with pytest.raises(AuthlibBaseError) as exc_info:
            client.parse_id_token(token, nonce="n")

    error = exc_info.value
    assert isinstance(error, OAuthError)
    assert isinstance(error, InvalidIDTokenError)
    # joserfc based error handling from Authlib 1.7+ keeps working
    assert isinstance(error, jose_error)
    assert isinstance(error, JoseError)
    assert isinstance(error.__cause__, jose_error)
    assert error.error == error.__cause__.error
    assert error.description == error.__cause__.description


def test_wrap_id_token_error():
    original = InvalidClaimError("iss")
    wrapped = wrap_id_token_error(original)

    assert isinstance(wrapped, InvalidIDTokenError)
    assert isinstance(wrapped, InvalidClaimError)
    assert wrapped.error == "invalid_claim"
    assert wrapped.description == original.description
    assert str(wrapped) == f"invalid_claim: {original.description}"
    # the generated subclass is cached per joserfc error class
    assert type(wrap_id_token_error(InvalidClaimError("aud"))) is type(wrapped)
