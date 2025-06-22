from unittest import TestCase
from unittest import mock

import pytest
from flask import Flask

from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey
from authlib.jose.errors import InvalidClaimError
from authlib.oidc.core.grants.util import generate_id_token

from ..util import get_bearer_token
from ..util import read_key_file

secret_key = JsonWebKey.import_key("secret", {"kty": "oct", "kid": "f"})


class FlaskUserMixinTest(TestCase):
    def test_fetch_userinfo(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            fetch_token=get_bearer_token,
            userinfo_endpoint="https://i.b/userinfo",
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

    def test_parse_id_token(self):
        token = get_bearer_token()
        id_token = generate_id_token(
            token,
            {"sub": "123"},
            secret_key,
            alg="HS256",
            iss="https://i.b",
            aud="dev",
            exp=3600,
            nonce="n",
        )

        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            fetch_token=get_bearer_token,
            jwks={"keys": [secret_key.as_dict()]},
            issuer="https://i.b",
            id_token_signing_alg_values_supported=["HS256", "RS256"],
        )
        with app.test_request_context():
            assert client.parse_id_token(token, nonce="n") is None

            token["id_token"] = id_token
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "123"

            claims_options = {"iss": {"value": "https://i.b"}}
            user = client.parse_id_token(
                token, nonce="n", claims_options=claims_options
            )
            assert user.sub == "123"

            claims_options = {"iss": {"value": "https://i.c"}}
            with pytest.raises(InvalidClaimError):
                client.parse_id_token(token, "n", claims_options)

    def test_parse_id_token_nonce_supported(self):
        token = get_bearer_token()
        id_token = generate_id_token(
            token,
            {"sub": "123", "nonce_supported": False},
            secret_key,
            alg="HS256",
            iss="https://i.b",
            aud="dev",
            exp=3600,
        )

        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            fetch_token=get_bearer_token,
            jwks={"keys": [secret_key.as_dict()]},
            issuer="https://i.b",
            id_token_signing_alg_values_supported=["HS256", "RS256"],
        )
        with app.test_request_context():
            token["id_token"] = id_token
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "123"

    def test_runtime_error_fetch_jwks_uri(self):
        token = get_bearer_token()
        id_token = generate_id_token(
            token,
            {"sub": "123"},
            secret_key,
            alg="HS256",
            iss="https://i.b",
            aud="dev",
            exp=3600,
            nonce="n",
        )

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
            issuer="https://i.b",
            id_token_signing_alg_values_supported=["HS256"],
        )
        with app.test_request_context():
            token["id_token"] = id_token
            with pytest.raises(RuntimeError):
                client.parse_id_token(token, "n")

    def test_force_fetch_jwks_uri(self):
        secret_keys = read_key_file("jwks_private.json")
        token = get_bearer_token()
        id_token = generate_id_token(
            token,
            {"sub": "123"},
            secret_keys,
            alg="RS256",
            iss="https://i.b",
            aud="dev",
            exp=3600,
            nonce="n",
        )

        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            fetch_token=get_bearer_token,
            jwks={"keys": [secret_key.as_dict()]},
            jwks_uri="https://i.b/jwks",
            issuer="https://i.b",
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
