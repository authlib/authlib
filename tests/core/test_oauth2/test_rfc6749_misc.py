import base64
import logging
import time
from types import SimpleNamespace

import pytest

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749 import AuthorizationSessionMixin
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc6749 import authenticate_client
from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import util
from authlib.oauth2.rfc6749.grants.base import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.grants.base import BaseGrant
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.requests import OAuth2Request


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


def test_prepare_token_request_with_list():
    """A list is sent as a repeated parameter."""
    body = parameters.prepare_token_request(
        "client_credentials", resource=["a", "", "b"], audience=("c",), scope=None
    )
    assert body == "grant_type=client_credentials&resource=a&resource=b&audience=c"


def test_list_to_scope():
    assert util.list_to_scope(["a", "b"]) == "a b"
    assert util.list_to_scope("a b") == "a b"
    assert util.list_to_scope(None) is None


def test_scope_to_list():
    assert util.scope_to_list("a b") == ["a", "b"]
    assert util.scope_to_list(["a", "b"]) == ["a", "b"]
    assert util.scope_to_list(None) is None


@pytest.mark.parametrize(
    "response_type,expected",
    [
        ("code", "code"),
        ("token id_token code", "code id_token token"),
        (" code  id_token ", "code id_token"),
        ("code code", "code code"),
        ("code\tid_token", "code\tid_token"),
        ("", ""),
        (None, None),
    ],
)
def test_normalize_response_type(response_type, expected):
    assert util.normalize_response_type(response_type) == expected


def test_check_authorization_endpoint_unsorted_response_types():
    """A grant can declare its response types in any order."""

    class CustomGrant(AuthorizationEndpointMixin):
        RESPONSE_TYPES = {"token code"}

    request = OAuth2Request("GET", "https://provider.test/authorize")
    for response_type in ("token code", "code token"):
        request.payload = BasicOAuth2Payload({"response_type": response_type})
        assert CustomGrant.check_authorization_endpoint(request)

    request.payload = BasicOAuth2Payload({"response_type": "code"})
    assert not CustomGrant.check_authorization_endpoint(request)


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


def test_extract_basic_authorization_not_utf8():
    """Credentials that are not valid UTF-8 are ignored instead of raising."""
    for raw in (b"\xff\xfe:secret", "\xe9t\xe9:secret".encode("latin-1")):
        text = f"Basic {base64.b64encode(raw).decode()}"
        assert util.extract_basic_authorization({"Authorization": text}) == (
            None,
            None,
        )


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


def test_grant_prompt_is_the_first_interaction():
    """grant.prompt is the first interaction, or None."""
    grant = BaseGrant(None, None)
    assert grant.interactions == []
    assert grant.prompt is None

    grant.interactions.extend(["login", "consent"])
    assert grant.prompt == "login"


def test_grant_prompt_setter_is_deprecated():
    """Setting grant.prompt is deprecated. It changes grant.prompt only, not
    grant.interactions."""
    grant = BaseGrant(None, None)
    grant.interactions.append("login")
    with pytest.warns(AuthlibDeprecationWarning, match="grant.interactions"):
        grant.prompt = "none"

    assert grant.prompt == "none"
    assert grant.interactions == ["login"]


def test_authorization_session_defaults():
    """By default, an authorization session knows no time, needs no consent,
    and no interaction is done."""
    session = AuthorizationSessionMixin()
    request = OAuth2Request("GET", "https://server.test/authorize")
    assert session.get_request_time(request) is None
    assert session.get_interaction_time(request, "login") is None
    assert not session.is_consent_needed(request)
    assert session.end_request(request) is None
    assert not session.is_interaction_done(request, "login")


def test_request_time_loader_error():
    """When the authorization session fails to give the start time, the next
    read tries again."""
    request = OAuth2Request("GET", "https://server.test/authorize")
    calls = []

    def loader(request):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("store down")

        return 1000

    request._request_time_loader = loader
    with pytest.raises(RuntimeError):
        assert request.request_time

    assert request.request_time == 1000
    assert request.request_time == 1000
    assert len(calls) == 2


FORGED_CLIENT_ID = "a\nAuthenticate 'admin' via \"client_secret_post\" success"


@pytest.mark.parametrize(
    "authenticate,oauth2_request",
    [
        (
            authenticate_client.authenticate_client_secret_post,
            SimpleNamespace(form={"client_id": FORGED_CLIENT_ID}),
        ),
        (
            authenticate_client.authenticate_none,
            SimpleNamespace(
                payload=SimpleNamespace(
                    client_id=FORGED_CLIENT_ID, data={"client_secret": "secret"}
                )
            ),
        ),
        (
            authenticate_client.authenticate_client_secret_basic,
            SimpleNamespace(
                headers={
                    "Authorization": "Basic "
                    + base64.b64encode(b"a%0Aforged:").decode()
                }
            ),
        ),
    ],
    ids=["client_secret_post", "none", "client_secret_basic"],
)
def test_client_id_logged_on_one_line(caplog, authenticate, oauth2_request):
    """A client_id with a line feed does not add a line to the logs."""
    with caplog.at_level(logging.DEBUG, logger=authenticate_client.log.name):
        authenticate(lambda client_id: None, oauth2_request)

    assert caplog.messages
    assert all("\n" not in message for message in caplog.messages)


def test_error_redirect():
    """An error with a redirect_uri redirects to it with 303."""
    error = errors.InvalidRequestError(
        state="s", redirect_uri="https://client.test/callback"
    )
    status_code, body, headers = error()
    assert status_code == 303
    assert body == ""
    assert headers == [
        (
            "Location",
            "https://client.test/callback?error=invalid_request&state=s",
        )
    ]
