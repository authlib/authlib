from authlib.oauth2.rfc6749.errors import MissingAuthorizationError
from authlib.oauth2.rfc6750.errors import InvalidTokenError


def test_invalid_token_error_extra_attributes_in_www_authenticate():
    """Extra attributes passed to InvalidTokenError should appear as
    individual key=value pairs in the WWW-Authenticate header."""
    error = InvalidTokenError(extra_attributes={"foo": "bar"})
    headers = dict(error.get_headers())
    www_authenticate = headers["WWW-Authenticate"]
    assert 'foo="bar"' in www_authenticate


def test_missing_authorization_error_with_realm():
    """A request without credentials gets a challenge with the realm and no
    error code."""
    error = MissingAuthorizationError("bearer", "example")
    status_code, body, headers = error()
    assert status_code == 401
    assert body == {}
    assert ("WWW-Authenticate", 'Bearer realm="example"') in headers
