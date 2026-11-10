import time
from unittest import mock

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.errors import BadSignatureError
from joserfc.errors import ExpiredTokenError
from joserfc.errors import InvalidClaimError
from joserfc.errors import InvalidKeyIdError
from joserfc.errors import JoseError
from joserfc.errors import MissingClaimError
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import OAuth
from authlib.oidc.core.grants.util import create_half_hash

from ..util import get_bearer_token
from ..util import raises_id_token_error
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
        with raises_id_token_error(InvalidClaimError):
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
            with raises_id_token_error(error):
                client.parse_id_token(token, nonce="n")

        # Only the application can explicitly omit the expected nonce.
        assert client.parse_id_token(token, nonce=None).sub == "123"


def test_unknown_kid_without_jwks_uri():
    """An unknown kid without jwks_uri raises an InvalidIDTokenError."""
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
        with raises_id_token_error(InvalidKeyIdError):
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


def _create_id_token(alg, key, iss="https://provider.test"):
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": iss,
        "aud": "dev",
        "iat": now,
        "exp": now + 3600,
        "nonce": "n",
    }
    return jwt.encode({"alg": alg}, claims, key, algorithms=[alg])


def _register_client(**kwargs):
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        **kwargs,
    )
    return app, client


def test_parse_id_token_default_algorithm():
    """Without id_token_signing_alg_values_supported, only RS256 is accepted."""
    app, client = _register_client()
    token = {"id_token": _create_id_token("HS256", secret_key)}
    with app.test_request_context():
        with raises_id_token_error(UnsupportedAlgorithmError):
            client.parse_id_token(token, nonce="n")


@pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
def test_parse_id_token_none_algorithm():
    """An unsigned ID token is refused, even if the provider allows none."""
    app, client = _register_client(
        id_token_signing_alg_values_supported=["RS256", "none"]
    )
    token = {"id_token": _create_id_token("none", None)}
    with app.test_request_context():
        with raises_id_token_error(UnsupportedAlgorithmError):
            client.parse_id_token(token, nonce="n")


def test_parse_id_token_claims_options_keep_issuer():
    """Claims options without iss keep the issuer check."""
    app, client = _register_client(id_token_signing_alg_values_supported=["HS256"])
    token = {"id_token": _create_id_token("HS256", secret_key, "https://other.test")}
    claims_options = {"email": {"essential": False}}
    with app.test_request_context():
        with raises_id_token_error(InvalidClaimError):
            client.parse_id_token(token, nonce="n", claims_options=claims_options)


@pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
def test_parse_id_token_only_none_algorithm():
    """When the provider lists only none, RS256 is used, not every algorithm."""
    app, client = _register_client(id_token_signing_alg_values_supported=["none"])
    token = {"id_token": _create_id_token("HS256", secret_key)}
    with app.test_request_context():
        with raises_id_token_error(UnsupportedAlgorithmError):
            client.parse_id_token(token, nonce="n")


def test_parse_id_token_algorithm_string():
    """A single algorithm can be given as a string."""
    app, client = _register_client(id_token_signing_alg_values_supported="HS256")
    token = {"id_token": _create_id_token("HS256", secret_key)}
    with app.test_request_context():
        assert client.parse_id_token(token, nonce="n").sub == "123"


def test_parse_id_token_claims_options_iss_without_value():
    """An iss option without value keeps the issuer of the metadata."""
    app, client = _register_client(id_token_signing_alg_values_supported=["HS256"])
    token = {"id_token": _create_id_token("HS256", secret_key, "https://other.test")}
    claims_options = {"iss": {"essential": True}}
    with app.test_request_context():
        with raises_id_token_error(InvalidClaimError):
            client.parse_id_token(token, nonce="n", claims_options=claims_options)
    assert claims_options == {"iss": {"essential": True}}


def test_parse_id_token_claims_options_not_modified():
    """The claims options of the application are not modified."""

    def validate_sub(claims, value):
        return value == "123"

    app, client = _register_client(id_token_signing_alg_values_supported=["HS256"])
    claims_options = {"sub": {"validate": validate_sub}}
    with app.test_request_context():
        for _ in range(2):
            token = {"id_token": _create_id_token("HS256", secret_key)}
            client.parse_id_token(token, nonce="n", claims_options=claims_options)
    assert claims_options == {"sub": {"validate": validate_sub}}


def test_parse_id_token_claims_options_iss_validate():
    """An iss option with a validate function replaces the metadata issuer."""
    app, client = _register_client(id_token_signing_alg_values_supported=["HS256"])
    token = {"id_token": _create_id_token("HS256", secret_key, "https://other.test")}
    claims_options = {"iss": {"validate": lambda claims, value: True}}
    with app.test_request_context():
        assert client.parse_id_token(token, "n", claims_options).sub == "123"


def test_parse_id_token_unknown_kid_refresh_interval():
    """An unknown kid fetches the JWK set again at most once per interval."""
    app, client = _register_client(
        id_token_signing_alg_values_supported=["HS256"],
        jwks_uri="https://provider.test/jwks",
    )
    now = int(time.time())
    claims = {"sub": "123", "iss": "https://provider.test", "aud": "dev"}
    claims.update({"iat": now, "exp": now + 3600, "nonce": "n"})
    id_token = jwt.encode({"alg": "HS256", "kid": "unknown"}, claims, secret_key)
    fetches = []

    def fake_send(sess, req, **kwargs):
        fetches.append(req.url)
        resp = mock.MagicMock()
        resp.json = lambda: {"keys": [secret_key.as_dict()]}
        resp.status_code = 200
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            for _ in range(3):
                with raises_id_token_error(InvalidKeyIdError):
                    client.parse_id_token({"id_token": id_token}, nonce="n")
            assert len(fetches) == 1

            client._jwk_set_refreshed_at -= client.jwks_refresh_interval
            with raises_id_token_error(InvalidKeyIdError):
                client.parse_id_token({"id_token": id_token}, nonce="n")
            assert len(fetches) == 2


@pytest.mark.parametrize(
    "case,cause",
    [("expired", ExpiredTokenError), ("bad_signature", BadSignatureError)],
)
def test_parse_id_token_errors_are_authlib_errors(case, cause):
    """ID token failures can be caught as AuthlibBaseError."""
    now = int(time.time())
    claims = {"sub": "123", "iss": "https://provider.test", "aud": "dev"}
    claims.update({"iat": now, "exp": now + 3600, "nonce": "n"})
    key = secret_key
    if case == "expired":
        claims.update({"iat": now - 7200, "exp": now - 3600})
    else:
        key = OctKey.import_key("another-oct-secret", {"kty": "oct", "kid": "f"})

    token = {"id_token": jwt.encode({"alg": "HS256"}, claims, key)}
    app, client = _register_client(id_token_signing_alg_values_supported=["HS256"])
    with app.test_request_context():
        with pytest.raises(AuthlibBaseError) as exc_info:
            client.parse_id_token(token, nonce="n")

    assert isinstance(exc_info.value.__cause__, cause)
    assert exc_info.value.error == cause.error
    assert exc_info.value.description == exc_info.value.__cause__.description


def test_parse_id_token_invalid_jwk_set():
    """An invalid JWK set from the provider raises an InvalidIDTokenError."""
    app = Flask(__name__)
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        jwks={"keys": [{"kty": "unknown"}]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256"],
    )
    token = {"id_token": _create_id_token("HS256", secret_key)}
    with app.test_request_context():
        with raises_id_token_error(JoseError):
            client.parse_id_token(token, nonce="n")
