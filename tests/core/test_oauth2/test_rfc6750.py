import pytest

from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750 import FormEncodedBodyToken
from authlib.oauth2.rfc6750.errors import InvalidTokenError

URLENCODED = "application/x-www-form-urlencoded"


class FormRequest(OAuth2Request):
    """A request with a form, for resource protector tests."""

    def __init__(self, method, headers, form):
        super().__init__(method, "https://resource.test/", headers=headers)
        self._form = form

    @property
    def form(self):
        return self._form


def create_protector(extension=True):
    """Create a resource protector with a bearer token validator."""
    protector = ResourceProtector()
    protector.register_token_validator(BearerTokenValidator())
    if extension:
        protector.register_extension(FormEncodedBodyToken())
    return protector


def test_invalid_token_error_extra_attributes_in_www_authenticate():
    """Extra attributes passed to InvalidTokenError should appear as
    individual key=value pairs in the WWW-Authenticate header."""
    error = InvalidTokenError(extra_attributes={"foo": "bar"})
    headers = dict(error.get_headers())
    www_authenticate = headers["WWW-Authenticate"]
    assert 'foo="bar"' in www_authenticate


@pytest.mark.parametrize(
    "content_type",
    [URLENCODED, "Application/X-WWW-Form-Urlencoded", URLENCODED + "; charset=utf-8"],
)
def test_form_body_token(content_type):
    """The access token is read from a form-encoded body."""
    protector = create_protector()
    request = FormRequest(
        "POST", {"Content-Type": content_type}, {"access_token": "a1"}
    )
    _, token_string = protector.parse_request_authorization(request)
    assert token_string == "a1"


def test_form_body_token_without_extension():
    """Without the extension, the body token is ignored."""
    protector = create_protector(extension=False)
    request = FormRequest("POST", {"Content-Type": URLENCODED}, {"access_token": "a1"})
    with pytest.raises(MissingAuthorizationError):
        protector.parse_request_authorization(request)


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
def test_form_body_token_ignored(method, content_type, form):
    """The body token is ignored when the request does not follow RFC 6750 §2.2."""
    protector = create_protector()
    headers = {"Content-Type": content_type} if content_type else {}
    request = FormRequest(method, headers, form)
    with pytest.raises(MissingAuthorizationError):
        protector.parse_request_authorization(request)


def test_form_body_token_and_header():
    """Sending the access token both in the header and in the body is refused."""
    protector = create_protector()
    request = FormRequest(
        "POST",
        {"Authorization": "Bearer a1", "Content-Type": URLENCODED},
        {"access_token": "a1"},
    )
    with pytest.raises(InvalidRequestError):
        protector.parse_request_authorization(request)


@pytest.mark.parametrize("request_class", [OAuth2Request, JsonRequest])
def test_form_body_token_without_form(request_class):
    """Requests without a form only use the Authorization header."""
    protector = create_protector()
    request = request_class(
        "POST",
        "https://resource.test/",
        headers={"Authorization": "Bearer a1", "Content-Type": URLENCODED},
    )
    _, token_string = protector.parse_request_authorization(request)
    assert token_string == "a1"
