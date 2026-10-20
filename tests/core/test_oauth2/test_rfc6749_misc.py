import base64
import time

import pytest

from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import util
from authlib.oauth2.rfc6749.hooks import Hookable
from authlib.oauth2.rfc6749.hooks import hooked
from authlib.oauth2.rfc6750 import BearerTokenValidator


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


def test_hooked_replace_and_success_path():
    """A replace hook wraps the method, and the after hook gets its result."""

    class MyService(Hookable):
        @hooked
        def compute(self, x):
            return x * 2

    svc = MyService()
    results = []
    svc.register_hook("after_compute", lambda instance, r: results.append(r))

    assert svc.compute(3) == 6
    assert results == [6]

    svc.register_hook(
        "replace_compute",
        lambda instance, original, x: original(x) + 10,
    )
    assert svc.compute(3) == 16


def test_hooked_with_explicit_parameters():
    """hooked accepts custom hook names."""

    class MyService(Hookable):
        @hooked(before="my_before")
        def work(self):
            return 42

    svc = MyService()
    calls = []
    svc.register_hook("my_before", lambda instance: calls.append("before"))

    assert svc.work() == 42
    assert calls == ["before"]


@pytest.mark.parametrize("request_class", [OAuth2Request, JsonRequest])
def test_parse_request_authorization_without_form(request_class):
    """Requests without a form only use the Authorization header."""
    protector = ResourceProtector()
    protector.register_token_validator(BearerTokenValidator())
    request = request_class(
        "POST",
        "https://resource.test/",
        headers={
            "Authorization": "Bearer a1",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    _, token_string = protector.parse_request_authorization(request)
    assert token_string == "a1"


class FormRequest(OAuth2Request):
    """A request with a form, for resource protector tests."""

    def __init__(self, method, headers, form):
        super().__init__(method, "https://resource.test/", headers=headers)
        self._form = form

    @property
    def form(self):
        return self._form


URLENCODED = "application/x-www-form-urlencoded"


@pytest.mark.parametrize(
    "content_type",
    [URLENCODED, "Application/X-WWW-Form-Urlencoded", URLENCODED + "; charset=utf-8"],
)
def test_parse_request_authorization_body_token(content_type):
    """The access token is read from a form-encoded body."""
    protector = ResourceProtector()
    protector.register_token_validator(BearerTokenValidator())
    request = FormRequest(
        "POST", {"Content-Type": content_type}, {"access_token": "a1"}
    )
    _, token_string = protector.parse_request_authorization(request)
    assert token_string == "a1"


@pytest.mark.parametrize(
    "method,content_type,form",
    [
        ("GET", URLENCODED, {"access_token": "a1"}),
        ("POST", "multipart/form-data", {"access_token": "a1"}),
        ("POST", "application/json", {"access_token": "a1"}),
        ("POST", None, {"access_token": "a1"}),
        ("POST", URLENCODED, {"access_token": ""}),
        ("POST", URLENCODED, {}),
    ],
)
def test_parse_request_authorization_ignored_body_token(method, content_type, form):
    """The body token is ignored when the request does not follow RFC 6750 §2.2."""
    protector = ResourceProtector()
    protector.register_token_validator(BearerTokenValidator())
    headers = {"Content-Type": content_type} if content_type else {}
    request = FormRequest(method, headers, form)
    with pytest.raises(errors.MissingAuthorizationError):
        protector.parse_request_authorization(request)
