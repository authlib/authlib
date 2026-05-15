import time
from unittest import mock

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import OctKey

from authlib.integrations.flask_client import OAuth
from authlib.oidc.core.grants.util import create_half_hash

from ..util import get_bearer_token


def _make_id_token(signing_key, kid=None):
    """Create a signed ID token.

    :param signing_key: OctKey used to sign the token.
    :param kid: kid to include in the JWT header.  None omits it.
    """
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "user-42",
        "nonce": "n",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    header = {"alg": "HS256"}
    if kid is not None:
        header["kid"] = kid
    token["id_token"] = jwt.encode(header, claims, signing_key)
    return token


def _fake_jwks_refresh(jwks_dict):
    """Create a mock send function that returns the given JWKS on refresh."""
    def fake_send(sess, req, **kwargs):
        resp = mock.MagicMock()
        resp.json = lambda: jwks_dict
        resp.status_code = 200
        return resp
    return fake_send


def _register_client(app, jwks, jwks_uri="https://provider.test/jwks"):
    oauth = OAuth(app)
    return oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks=jwks,
        jwks_uri=jwks_uri,
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256"],
    )


def test_default_raises_on_kid_mismatch():
    """Default behavior: kid mismatch raises InvalidKeyIdError after refresh."""
    signing_key = OctKey.import_key("secret-for-mismatch-test")
    token = _make_id_token(signing_key, kid="token-kid-1")
    app = Flask(__name__)
    app.secret_key = "!"

    key_dict = signing_key.as_dict()
    key_dict["kid"] = "different-kid"
    extra_key = OctKey.import_key("extra-key-material-xxxxx")
    extra_dict = extra_key.as_dict()
    extra_dict["kid"] = "extra-kid"
    jwks = {"keys": [key_dict, extra_dict]}
    client = _register_client(app, jwks)

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", _fake_jwks_refresh(jwks)):
            with pytest.raises(InvalidKeyIdError):
                client.parse_id_token(token, nonce="n")


def test_no_kid_in_token_multiple_jwks_keys_needs_fallback():
    """Token without kid + multiple JWKS keys raises unless fallback enabled."""
    signing_key = OctKey.import_key("secret-for-multi-key-test")
    token = _make_id_token(signing_key, kid=None)
    app = Flask(__name__)
    app.secret_key = "!"

    other_key = OctKey.import_key("other-key-material-xxxxx")
    other_dict = other_key.as_dict()
    other_dict["kid"] = "key-1"
    correct_dict = signing_key.as_dict()
    correct_dict["kid"] = "key-2"
    jwks = {"keys": [other_dict, correct_dict]}

    client = _register_client(app, jwks)
    client.should_try_all_keys = lambda: True

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", _fake_jwks_refresh(jwks)):
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "user-42"


def test_key_rotation_resolved_by_refresh():
    """JWKS refresh resolves kid mismatch when provider rotated keys."""
    signing_key = OctKey.import_key("secret-for-rotation-test")
    token = _make_id_token(signing_key, kid="new-kid")
    app = Flask(__name__)
    app.secret_key = "!"

    # Initial JWKS has old keys that cannot verify the token
    old_key = OctKey.import_key("old-key-material-xxxxx")
    old_dict = old_key.as_dict()
    old_dict["kid"] = "old-kid"
    old_key2 = OctKey.import_key("old-key-material-yyyyy")
    old_dict2 = old_key2.as_dict()
    old_dict2["kid"] = "old-kid-2"

    # After refresh: correct key with matching kid + another key
    correct_dict = signing_key.as_dict()
    correct_dict["kid"] = "new-kid"

    client = _register_client(app, {"keys": [old_dict, old_dict2]})

    with app.test_request_context():
        with mock.patch(
            "requests.sessions.Session.send",
            _fake_jwks_refresh({"keys": [correct_dict, old_dict2]}),
        ):
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "user-42"


def test_try_all_keys_with_kid_mismatch():
    """With should_try_all_keys enabled, fallback finds the correct key."""
    signing_key = OctKey.import_key("secret-for-try-all-test")
    token = _make_id_token(signing_key, kid="nonexistent-kid")
    app = Flask(__name__)
    app.secret_key = "!"

    wrong_key = OctKey.import_key("wrong-secret-material")
    correct_dict = signing_key.as_dict()
    correct_dict["kid"] = "other-kid"
    jwks = {"keys": [wrong_key.as_dict(), correct_dict]}

    client = _register_client(app, jwks)
    client.should_try_all_keys = lambda: True

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", _fake_jwks_refresh(jwks)):
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "user-42"


def test_try_all_keys_when_jwks_key_has_no_kid():
    """With should_try_all_keys enabled, works when JWKS keys lack kid."""
    signing_key = OctKey.import_key("secret-for-jwks-no-kid")
    token = _make_id_token(signing_key, kid="token-kid")
    app = Flask(__name__)
    app.secret_key = "!"

    # JWKS keys have no kid — triggers InvalidKeyIdError for token with kid
    wrong_key = OctKey.import_key("wrong-key-for-no-kid-test")
    jwks = {"keys": [wrong_key.as_dict(), signing_key.as_dict()]}
    client = _register_client(app, jwks)
    client.should_try_all_keys = lambda: True

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", _fake_jwks_refresh(jwks)):
            user = client.parse_id_token(token, nonce="n")
            assert user.sub == "user-42"


def test_try_all_keys_no_valid_key_raises():
    """With should_try_all_keys enabled, raises if no key verifies."""
    signing_key = OctKey.import_key("secret-for-no-match-test")
    token = _make_id_token(signing_key, kid="token-kid")
    app = Flask(__name__)
    app.secret_key = "!"

    wrong_key1 = OctKey.import_key("completely-different-secret")
    wrong_dict1 = wrong_key1.as_dict()
    wrong_dict1["kid"] = "wrong-1"
    wrong_key2 = OctKey.import_key("another-different-secret")
    wrong_dict2 = wrong_key2.as_dict()
    wrong_dict2["kid"] = "wrong-2"
    jwks = {"keys": [wrong_dict1, wrong_dict2]}

    client = _register_client(app, jwks)
    client.should_try_all_keys = lambda: True

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", _fake_jwks_refresh(jwks)):
            with pytest.raises(InvalidKeyIdError):
                client.parse_id_token(token, nonce="n")


def test_no_jwks_uri_raises_runtime_error():
    """When jwks_uri is absent, JWKS refresh raises RuntimeError."""
    signing_key = OctKey.import_key("secret-for-no-uri-test")
    token = _make_id_token(signing_key, kid="token-kid")
    app = Flask(__name__)
    app.secret_key = "!"

    # JWKS has the correct key material but wrong kid, triggering refresh
    key_dict = signing_key.as_dict()
    key_dict["kid"] = "embedded-kid"
    extra_key = OctKey.import_key("extra-no-uri-key-material")
    extra_dict = extra_key.as_dict()
    extra_dict["kid"] = "extra-kid"

    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [key_dict, extra_dict]},
        # No jwks_uri provided
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256"],
    )

    with app.test_request_context():
        with pytest.raises(RuntimeError, match="jwks_uri"):
            client.parse_id_token(token, nonce="n")
