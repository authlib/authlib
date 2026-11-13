import pytest

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenGenerator
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


def test_empty_form_body_token_and_header():
    """An empty body token is ignored, so the header token is used."""
    protector = create_protector()
    request = FormRequest(
        "POST",
        {"Authorization": "Bearer a1", "Content-Type": URLENCODED},
        {"access_token": ""},
    )
    _, token_string = protector.parse_request_authorization(request)
    assert token_string == "a1"


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


def test_missing_authorization_error_with_realm():
    """A request without credentials gets a challenge with the realm and no
    error code."""
    error = MissingAuthorizationError("bearer", "example")
    status_code, body, headers = error()
    assert status_code == 401
    assert body == {}
    assert ("WWW-Authenticate", 'Bearer realm="example"') in headers


class ScopeClient:
    """Client that allows every scope."""

    def get_allowed_scope(self, scope):
        """Return the requested scope."""
        return scope or "profile"


def test_access_token_generator_receives_expires_in():
    """The access token generator receives the lifetime of the token."""

    def access_token_generator(client, grant_type, user, scope, expires_in, request):
        return f"token-{expires_in}"

    generator = BearerTokenGenerator(access_token_generator)
    token = generator.generate("client_credentials", ScopeClient(), expires_in=300)

    assert token["access_token"] == "token-300"
    assert token["expires_in"] == 300


def test_access_token_generator_with_kwargs():
    """An access token generator with **kwargs receives the lifetime."""

    def access_token_generator(**kwargs):
        return f"token-{kwargs['expires_in']}"

    generator = BearerTokenGenerator(access_token_generator, expires_generator=600)
    token = generator.generate("client_credentials", ScopeClient())

    assert token["access_token"] == "token-600"


def test_access_token_generator_without_expires_in():
    """An access token generator without expires_in is deprecated but works."""

    def access_token_generator(client, grant_type, user, scope):
        return "token"

    with pytest.warns(AuthlibDeprecationWarning, match="expires_in"):
        generator = BearerTokenGenerator(access_token_generator)

    token = generator.generate("client_credentials", ScopeClient(), expires_in=300)
    assert token["access_token"] == "token"
    assert token["expires_in"] == 300


def test_access_token_generator_without_signature():
    """A callable without an introspectable signature is called as before."""

    class Generator:
        """Callable whose signature cannot be read."""

        __signature__ = "invalid"

        def __call__(self, client, grant_type, user, scope):
            return "token"

    with pytest.warns(AuthlibDeprecationWarning, match="expires_in"):
        generator = BearerTokenGenerator(Generator())

    token = generator.generate("client_credentials", ScopeClient())
    assert token["access_token"] == "token"


def test_generators_receive_request():
    """The access and refresh token generators receive the request."""
    request = OAuth2Request("POST", "https://provider.test/token")

    def access_token_generator(client, grant_type, user, scope, expires_in, request):
        return f"access-{request.method}"

    def refresh_token_generator(client, grant_type, user, scope, request):
        return f"refresh-{request.method}"

    generator = BearerTokenGenerator(access_token_generator, refresh_token_generator)
    token = generator("client_credentials", ScopeClient(), request=request)

    assert token["access_token"] == "access-POST"
    assert token["refresh_token"] == "refresh-POST"


def test_generators_without_request():
    """Generators without a request argument are deprecated but still work."""

    def access_token_generator(client, grant_type, user, scope, expires_in):
        return "access"

    def refresh_token_generator(client, grant_type, user, scope):
        return "refresh"

    with pytest.warns(AuthlibDeprecationWarning, match="'request'") as record:
        generator = BearerTokenGenerator(
            access_token_generator, refresh_token_generator
        )

    assert len(record) == 2
    token = generator.generate("client_credentials", ScopeClient())
    assert token["access_token"] == "access"
    assert token["refresh_token"] == "refresh"


def test_generate_override_without_request():
    """A BearerTokenGenerator.generate override without a request parameter is
    deprecated but still works."""

    class Generator(BearerTokenGenerator):
        def generate(
            self,
            grant_type,
            client,
            user=None,
            scope=None,
            expires_in=None,
            include_refresh_token=True,
        ):
            return {"access_token": grant_type}

    with pytest.warns(AuthlibDeprecationWarning, match="'request'"):
        generator = Generator(None)

    token = generator("client_credentials", ScopeClient(), request=object())
    assert token == {"access_token": "client_credentials"}


def test_no_access_token_generator():
    """A generator without access token generator can be created."""
    generator = BearerTokenGenerator(None)
    assert generator.access_token_generator is None
