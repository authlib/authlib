import time
from unittest import mock

import pytest
import requests
from flask import Flask
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import InvalidKeyIdError
from joserfc.errors import MissingClaimError
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client import OAuthError
from authlib.oidc.core.grants.util import create_half_hash

from ..util import get_bearer_token
from ..util import get_bearer_token_with_claims
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
        with pytest.raises(UnsupportedAlgorithmError):
            client.parse_id_token(token, nonce="n")


@pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
def test_parse_id_token_none_algorithm():
    """An unsigned ID token is refused, even if the provider allows none."""
    app, client = _register_client(
        id_token_signing_alg_values_supported=["RS256", "none"]
    )
    token = {"id_token": _create_id_token("none", None)}
    with app.test_request_context():
        with pytest.raises(UnsupportedAlgorithmError):
            client.parse_id_token(token, nonce="n")


def test_parse_id_token_claims_options_keep_issuer():
    """Claims options without iss keep the issuer check."""
    app, client = _register_client(id_token_signing_alg_values_supported=["HS256"])
    token = {"id_token": _create_id_token("HS256", secret_key, "https://other.test")}
    claims_options = {"email": {"essential": False}}
    with app.test_request_context():
        with pytest.raises(InvalidClaimError):
            client.parse_id_token(token, nonce="n", claims_options=claims_options)


@pytest.mark.filterwarnings("ignore::joserfc.errors.SecurityWarning")
def test_parse_id_token_only_none_algorithm():
    """When the provider lists only none, RS256 is used, not every algorithm."""
    app, client = _register_client(id_token_signing_alg_values_supported=["none"])
    token = {"id_token": _create_id_token("HS256", secret_key)}
    with app.test_request_context():
        with pytest.raises(UnsupportedAlgorithmError):
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
        with pytest.raises(InvalidClaimError):
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
                with pytest.raises(InvalidKeyIdError):
                    client.parse_id_token({"id_token": id_token}, nonce="n")
            assert len(fetches) == 1

            client._jwk_set_refreshed_at -= client.jwks_refresh_interval
            with pytest.raises(InvalidKeyIdError):
                client.parse_id_token({"id_token": id_token}, nonce="n")
            assert len(fetches) == 2


def make_signed_userinfo_client(client_id="dev"):
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id=client_id,
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        userinfo_endpoint="https://provider.test/userinfo",
        userinfo_signing_alg_values_supported=["HS256"],
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


def test_fetch_userinfo_signed_jwt_rejects_missing_sub():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
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
            with pytest.raises(MissingClaimError):
                client.userinfo()


def test_fetch_userinfo_signed_jwt_rejects_missing_iss():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
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
            with pytest.raises(MissingClaimError):
                client.userinfo()


def test_fetch_userinfo_signed_jwt_rejects_missing_aud():
    app, client = make_signed_userinfo_client()

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
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
            with pytest.raises(MissingClaimError):
                client.userinfo()


def test_fetch_userinfo_json_without_sub_still_returns():
    app, client = make_signed_userinfo_client()

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.json = lambda: {"name": "John Doe"}
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            user = client.userinfo()
            assert user["name"] == "John Doe"
            assert user.get("sub") is None


def test_fetch_userinfo_signed_jwt_requires_aud_without_client_id():
    app, client = make_signed_userinfo_client(client_id=None)

    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
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
            with pytest.raises(MissingClaimError):
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
    client.server_metadata["userinfo_signing_alg_values_supported"] = ["RS256"]

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


def test_fetch_userinfo_signed_jwt_default_algorithms():
    """Without signing metadata, the default algorithms of joserfc are accepted."""
    app, client = make_signed_userinfo_client()
    del client.server_metadata["userinfo_signing_alg_values_supported"]
    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "exp": now + 60,
    }

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(encode_signed_userinfo(claims)),
        ):
            assert client.userinfo().sub == "123"


def test_fetch_userinfo_registered_signed_response_alg():
    """A response signed with the registered algorithm is accepted."""
    app, client = make_signed_userinfo_client()
    client.server_metadata["userinfo_signed_response_alg"] = "HS256"
    del client.server_metadata["userinfo_signing_alg_values_supported"]
    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "exp": now + 60,
    }

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(encode_signed_userinfo(claims)),
        ):
            assert client.userinfo().sub == "123"


def test_fetch_userinfo_json_with_none_signed_response_alg():
    """A registered none algorithm accepts JSON responses."""
    app, client = make_signed_userinfo_client()
    client.server_metadata["userinfo_signed_response_alg"] = "none"

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.json = lambda: {"sub": "123"}
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            assert client.userinfo().sub == "123"


def test_fetch_userinfo_signed_response_alg():
    """The registered userinfo_signed_response_alg is the only accepted one."""
    app, client = make_signed_userinfo_client()
    client.server_metadata["userinfo_signed_response_alg"] = "RS256"
    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "123",
        "exp": now + 60,
    }

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(encode_signed_userinfo(claims)),
        ):
            with pytest.raises(UnsupportedAlgorithmError):
                client.userinfo()


def test_fetch_userinfo_json_with_signed_response_alg():
    """A JSON response is refused when userinfo_signed_response_alg is set."""
    app, client = make_signed_userinfo_client()
    client.server_metadata["userinfo_signed_response_alg"] = "HS256"

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.json = lambda: {"sub": "123"}
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            with pytest.raises(OAuthError, match="not signed"):
                client.userinfo()


def make_json_userinfo_response(payload):
    """Return a fake send function that answers with a JSON UserInfo
    response.
    """

    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.json = lambda: payload
        return resp

    return fake_send


@pytest.mark.parametrize(
    "token",
    [
        get_bearer_token_with_claims(),
        get_bearer_token(),
        None,
    ],
    ids=["id-token", "no-id-token", "no-token"],
)
def test_fetch_userinfo_sub_accepted(token):
    """The UserInfo response is returned when its sub is the ID token sub,
    or when no ID token is known.
    """
    app, client = make_signed_userinfo_client()
    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_json_userinfo_response({"sub": "123"}),
        ):
            user = client.userinfo(token=token)
            assert user.sub == "123"


@pytest.mark.parametrize(
    "payload",
    [{"sub": "456"}, {"name": "John Doe"}],
    ids=["other-sub", "missing-sub"],
)
def test_fetch_userinfo_json_sub_mismatch(payload):
    """A JSON UserInfo response without the ID token sub is refused."""
    app, client = make_signed_userinfo_client()
    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_json_userinfo_response(payload),
        ):
            with pytest.raises(OAuthError, match="sub"):
                client.userinfo(token=get_bearer_token_with_claims())


def test_fetch_userinfo_signed_jwt_sub_mismatch():
    """A signed UserInfo response with another sub is refused."""
    app, client = make_signed_userinfo_client()
    now = int(time.time())
    claims = {
        "iss": "https://provider.test",
        "aud": "dev",
        "sub": "456",
        "iat": now,
        "exp": now + 3600,
    }
    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_signed_userinfo_response(encode_signed_userinfo(claims)),
        ):
            with pytest.raises(OAuthError, match="sub"):
                client.userinfo(token=get_bearer_token_with_claims())


def test_fetch_userinfo_sub_mismatch_with_stored_token():
    """The sub is checked against the token stored by authorize_access_token,
    when no token is passed.
    """
    app, client = make_signed_userinfo_client()
    with app.test_request_context():
        client.token = get_bearer_token_with_claims()
        with mock.patch(
            "requests.sessions.Session.send",
            make_json_userinfo_response({"sub": "456"}),
        ):
            with pytest.raises(OAuthError, match="sub"):
                client.userinfo()


def test_fetch_userinfo_sub_ignores_claims_without_sub():
    """Token claims without sub are not compared."""
    app, client = make_signed_userinfo_client()
    token = get_bearer_token()
    token["userinfo"] = {"login": "john"}
    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            make_json_userinfo_response({"sub": "123"}),
        ):
            user = client.userinfo(token=token)
            assert user.sub == "123"
