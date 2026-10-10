import time
import urllib.parse
from unittest import mock

import pytest
import requests
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.integrations.requests_client import AssertionSession


@pytest.fixture
def token():
    return {
        "token_type": "Bearer",
        "access_token": "a",
        "refresh_token": "b",
        "expires_in": "3600",
        "expires_at": int(time.time()) + 3600,
    }


def test_refresh_token(token):
    def verifier(r, **kwargs):
        resp = mock.MagicMock()
        resp.status_code = 200
        if r.url == "https://provider.test/token":
            assert "assertion=" in r.body
            resp.json = lambda: token
        return resp

    sess = AssertionSession(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
    )
    sess.send = verifier
    sess.get("https://provider.test")

    # trigger more case
    now = int(time.time())
    sess = AssertionSession(
        "https://provider.test/token",
        issuer="foo",
        subject=None,
        audience="foo",
        issued_at=now,
        expires_at=now + 3600,
        header={"alg": "HS256"},
        key="secret",
        scope="email",
        claims={"test_mode": "true"},
    )
    sess.send = verifier
    sess.get("https://provider.test")
    # trigger for branch test case
    sess.get("https://provider.test")


def test_without_alg():
    sess = AssertionSession(
        "https://provider.test/token",
        grant_type=AssertionSession.JWT_BEARER_GRANT_TYPE,
        issuer="foo",
        subject="foo",
        audience="foo",
        key="secret",
    )
    with pytest.raises(ValueError):
        sess.get("https://provider.test")


def test_assertion_includes_default_jti(token):
    """Verify that AssertionSession generates a jti in the JWT assertion."""
    assertions = []

    def verifier(r, **kwargs):
        resp = mock.MagicMock()
        resp.status_code = 200
        if r.url == "https://provider.test/token":
            body = urllib.parse.parse_qs(r.body)
            assertions.append(body["assertion"][0])
            resp.json = lambda: token
        return resp

    sess = AssertionSession(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
    )
    sess.send = verifier
    sess.get("https://provider.test")

    assert len(assertions) == 1
    key = OctKey.import_key("secret")
    claims = jwt.decode(assertions[0], key).claims
    assert "jti" in claims
    assert len(claims["jti"]) == 36


def test_assertion_jti_is_unique_per_refresh(token):
    """Verify that each token refresh generates a new unique jti."""
    assertions = []

    def verifier(r, **kwargs):
        resp = mock.MagicMock()
        resp.status_code = 200
        if r.url == "https://provider.test/token":
            body = urllib.parse.parse_qs(r.body)
            assertions.append(body["assertion"][0])
            resp.json = lambda: {
                **token,
                "expires_in": "1",
                "expires_at": int(time.time()) - 1,
            }
        return resp

    sess = AssertionSession(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
    )
    sess.send = verifier
    sess.get("https://provider.test")
    sess.get("https://provider.test")

    assert len(assertions) == 2
    key = OctKey.import_key("secret")
    jti1 = jwt.decode(assertions[0], key).claims["jti"]
    jti2 = jwt.decode(assertions[1], key).claims["jti"]
    assert jti1
    assert jti2
    assert jti1 != jti2


def test_assertion_custom_jti_is_preserved(token):
    """Verify that a user-provided jti claim is not overwritten."""
    assertions = []

    def verifier(r, **kwargs):
        resp = mock.MagicMock()
        resp.status_code = 200
        if r.url == "https://provider.test/token":
            body = urllib.parse.parse_qs(r.body)
            assertions.append(body["assertion"][0])
            resp.json = lambda: token
        return resp

    sess = AssertionSession(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
        claims={"jti": "my-custom-jti-value"},
    )
    sess.send = verifier
    sess.get("https://provider.test")

    assert len(assertions) == 1
    key = OctKey.import_key("secret")
    claims = jwt.decode(assertions[0], key).claims
    assert claims["jti"] == "my-custom-jti-value"


def test_refresh_token_non_json_error_response():
    def fake_send(r, **kwargs):
        resp = requests.Response()
        resp.status_code = 429
        resp._content = b"429 Too Many Requests"
        resp.url = r.url
        return resp

    sess = AssertionSession(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
    )
    sess.send = fake_send
    with pytest.raises(requests.HTTPError):
        sess.refresh_token()
