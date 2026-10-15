import time
from unittest import mock

import pytest
import requests
from flask import Flask
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError
from joserfc.errors import UnsupportedAlgorithmError
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


def make_signed_userinfo_client():
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
        userinfo_endpoint="https://provider.test/userinfo",
    )
    return app, client


def encode_signed_userinfo(claims):
    return jwt.encode({"alg": "HS256", "kid": "f"}, claims, secret_key)


def make_signed_userinfo_response(id_token, content_type="application/jwt"):
    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": content_type}
        resp.text = id_token
        return resp

    return fake_send


def test_fetch_userinfo_signed_jwt_response():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "name": "John Doe",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = encode_signed_userinfo(claims)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token),
        ):
            user = client.userinfo()
            assert user.sub == "123"
            assert user["name"] == "John Doe"


def test_fetch_userinfo_signed_jwt_aud_accepts_list():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": ["dev", "other-rp"],
        "sub": "123",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = encode_signed_userinfo(claims)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token),
        ):
            user = client.userinfo()
            assert user.sub == "123"


def test_fetch_userinfo_signed_jwt_rejects_wrong_issuer():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://evil.test",
        "aud": "dev",
        "sub": "123",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = encode_signed_userinfo(claims)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token),
        ):
            with pytest.raises(InvalidClaimError):
                client.userinfo()


def test_fetch_userinfo_signed_jwt_rejects_wrong_audience():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "another-client",
        "sub": "123",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = encode_signed_userinfo(claims)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token),
        ):
            with pytest.raises(InvalidClaimError):
                client.userinfo()


def test_fetch_userinfo_signed_jwt_rejects_bad_signature():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "iat": now,
        "exp": now + 3600,
    }
    attacker_key = OctKey.import_key("attacker-oct-secret", {"kty": "oct", "kid": "f"})
    id_token = jwt.encode({"alg": "HS256", "kid": "f"}, claims, attacker_key)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token),
        ):
            from joserfc.errors import BadSignatureError

            with pytest.raises(BadSignatureError):
                client.userinfo()


def test_fetch_userinfo_content_type_with_charset():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = encode_signed_userinfo(claims)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token, "application/jwt; charset=utf-8"),
        ):
            user = client.userinfo()
            assert user.sub == "123"


def test_fetch_userinfo_json_still_works():
    app, client = make_signed_userinfo_client()

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.json = lambda: {"sub": "456"}
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user.sub == "456"


def test_fetch_userinfo_signed_jwt_rejects_unsupported_alg():
    app, client = make_signed_userinfo_client()
    # restrict the userinfo signing algs to RS256; the HS256 token must then
    # be rejected, mirroring id_token_signing_alg_values_supported handling
    client.server_metadata["userinfo_signing_alg_values_supported"] = ["RS256"]

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = encode_signed_userinfo(claims)

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(id_token),
        ):
            with pytest.raises(UnsupportedAlgorithmError):
                client.userinfo()


def test_fetch_userinfo_signed_jwt_via_jwks_uri_key_rotation():
    app, client = make_signed_userinfo_client()
    # token signed by a key absent from the cached jwks dict; the client must
    # raise InvalidKeyIdError internally and force a refresh from jwks_uri
    secret_keys = KeySet.import_key_set(read_key_file("jwks_private.json"))

    client.server_metadata["jwks"] = {"keys": [secret_key.as_dict()]}
    client.server_metadata["jwks_uri"] = "https://provider.test/jwks"

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "name": "John Doe",
        "iat": now,
        "exp": now + 3600,
    }
    id_token = jwt.encode({"alg": "RS256"}, claims, secret_keys)

    def fake_send(sess, req, **kwargs):
        if "jwks" in req.url:
            resp = mock.MagicMock()
            resp.json = lambda: read_key_file("jwks_public.json")
            resp.status_code = 200
            return resp
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/jwt"}
        resp.text = id_token
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user.sub == "123"
            assert user["name"] == "John Doe"
