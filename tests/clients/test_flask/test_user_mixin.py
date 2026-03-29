import time
from unittest import mock

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

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


def test_parse_id_token_nonce_supported():
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
        user = client.parse_id_token(token, nonce="n")
        assert user.sub == "123"


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
