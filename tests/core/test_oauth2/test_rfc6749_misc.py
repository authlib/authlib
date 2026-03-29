import base64
import time

import pytest

from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import util


def test_parse_authorization_code_response():
    with pytest.raises(errors.MissingCodeException):
        parameters.parse_authorization_code_response(
            "https://provider.test/?state=c",
        )

    with pytest.raises(errors.MismatchingStateException):
        parameters.parse_authorization_code_response(
            "https://provider.test/?code=a&state=c",
            "b",
        )

    url = "https://provider.test/?code=a&state=c"
    rv = parameters.parse_authorization_code_response(url, "c")
    assert rv == {"code": "a", "state": "c"}


def test_parse_implicit_response():
    with pytest.raises(errors.MissingTokenException):
        parameters.parse_implicit_response(
            "https://provider.test/#a=b",
        )

    with pytest.raises(errors.MissingTokenTypeException):
        parameters.parse_implicit_response(
            "https://provider.test/#access_token=a",
        )

    with pytest.raises(errors.MismatchingStateException):
        parameters.parse_implicit_response(
            "https://provider.test/#access_token=a&token_type=bearer&state=c",
            "abc",
        )

    url = "https://provider.test/#access_token=a&token_type=bearer&state=c"
    rv = parameters.parse_implicit_response(url, "c")
    assert rv == {"access_token": "a", "token_type": "bearer", "state": "c"}


def test_prepare_grant_uri():
    grant_uri = parameters.prepare_grant_uri(
        "https://provider.test/authorize", "dev", "code", max_age=0, resource=["a", "b"]
    )
    assert (
        grant_uri
        == "https://provider.test/authorize?response_type=code&client_id=dev&max_age=0&resource=a&resource=b"
    )


def test_list_to_scope():
    assert util.list_to_scope(["a", "b"]) == "a b"
    assert util.list_to_scope("a b") == "a b"
    assert util.list_to_scope(None) is None


def test_scope_to_list():
    assert util.scope_to_list("a b") == ["a", "b"]
    assert util.scope_to_list(["a", "b"]) == ["a", "b"]
    assert util.scope_to_list(None) is None


def test_extract_basic_authorization():
    assert util.extract_basic_authorization({}) == (None, None)
    assert util.extract_basic_authorization({"Authorization": "invalid"}) == (
        None,
        None,
    )

    text = "Basic invalid-base64"
    assert util.extract_basic_authorization({"Authorization": text}) == (None, None)

    text = "Basic {}".format(base64.b64encode(b"a").decode())
    assert util.extract_basic_authorization({"Authorization": text}) == ("a", None)

    text = "Basic {}".format(base64.b64encode(b"a:b").decode())
    assert util.extract_basic_authorization({"Authorization": text}) == ("a", "b")


def test_oauth2token_is_expired_with_expires_at_zero():
    """Token with expires_at=0 (epoch) should be considered expired."""
    token = OAuth2Token({"access_token": "a", "expires_at": 0})
    assert token["expires_at"] == 0
    assert token.is_expired() is True


def test_oauth2token_is_expired_with_expires_at_none():
    """Token with no expires_at should return None for is_expired."""
    token = OAuth2Token({"access_token": "a"})
    assert token.is_expired() is None


def test_oauth2token_is_expired_with_valid_token():
    """Token with future expires_at should not be expired."""
    future = int(time.time()) + 7200
    token = OAuth2Token({"access_token": "a", "expires_at": future})
    assert token.is_expired() is False
