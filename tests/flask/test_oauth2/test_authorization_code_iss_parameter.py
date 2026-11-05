import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import ImplicitGrant
from authlib.oauth2.rfc9207 import IssuerParameter as _IssuerParameter
from tests.util import parse_form

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import register_form_post

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id"


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class IssuerParameter(_IssuerParameter):
    def get_issuer(self) -> str:
        return "https://auth.test"


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(ImplicitGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code", "token"],
            "grant_types": ["authorization_code", "implicit"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_rfc9207_enabled_success(test_client, server):
    """Check that when RFC9207 is implemented,
    the authorization response has an ``iss`` parameter."""

    server.register_extension(IssuerParameter())
    url = authorize_url + "&state=bar"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "iss=https%3A%2F%2Fauth.test" in rv.location


def test_rfc9207_disabled_success_no_iss(test_client):
    """Check that when RFC9207 is not implemented,
    the authorization response contains no ``iss`` parameter."""

    url = authorize_url + "&state=bar"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "iss=" not in rv.location


def test_rfc9207_enabled_error(test_client, server):
    """Check that when RFC9207 is implemented,
    the authorization response has an ``iss`` parameter,
    even when an error is returned."""

    server.register_extension(IssuerParameter())
    rv = test_client.post(authorize_url)
    assert "error=access_denied" in rv.location
    assert "iss=https%3A%2F%2Fauth.test" in rv.location


def test_rfc9207_disbled_error_no_iss(test_client):
    """Check that when RFC9207 is not implemented,
    the authorization response contains no ``iss`` parameter,
    even when an error is returned."""

    rv = test_client.post(authorize_url)
    assert "error=access_denied" in rv.location
    assert "iss=" not in rv.location


def test_rfc9207_fragment(test_client, server, client, db):
    """The iss parameter is in the fragment, with the other parameters."""
    client.set_client_metadata(
        {**client.client_metadata, "token_endpoint_auth_method": "none"}
    )
    db.session.commit()
    server.register_extension(IssuerParameter())
    rv = test_client.post(
        "/oauth/authorize?response_type=token&client_id=client-id",
        data={"user_id": "1"},
    )
    location = urlparse.urlparse(rv.location)
    assert "iss=" not in location.query
    params = dict(url_decode(location.fragment))
    assert params["iss"] == "https://auth.test"
    assert "access_token" in params


@pytest.mark.parametrize("issuer_first", [True, False])
@pytest.mark.parametrize("user_id", ["1", ""])
def test_rfc9207_form_post(test_client, server, issuer_first, user_id):
    """The iss parameter is in the form of a form_post response, granted or
    denied, whatever the registration order of the extensions."""
    if issuer_first:
        server.register_extension(IssuerParameter())
        register_form_post(server)
    else:
        register_form_post(server)
        server.register_extension(IssuerParameter())

    rv = test_client.post(
        authorize_url + "&response_mode=form_post", data={"user_id": user_id}
    )
    form = parse_form(rv.data)
    assert form.values["iss"] == "https://auth.test"
    assert ("code" in form.values) is bool(user_id)
    assert ("error" in form.values) is not bool(user_id)


def test_rfc9207_consent_error(test_client, server):
    """The iss parameter is in the errors of the consent page."""
    server.scopes_supported = ["profile", "address"]
    server.register_extension(IssuerParameter())
    rv = test_client.get(authorize_url + "&scope=invalid&user_id=1")
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_scope"
    assert params["iss"] == "https://auth.test"


class OtherIssuerParameter(_IssuerParameter):
    def get_issuer(self) -> str:
        return "https://other.test"


def test_rfc9207_single_iss(test_client, server):
    """The response has a single iss parameter, with the issuer of the server."""
    server.register_extension(OtherIssuerParameter())
    server.register_extension(IssuerParameter())
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    query = urlparse.urlparse(rv.location).query
    assert query.count("iss=") == 1
    assert dict(url_decode(query))["iss"] == "https://auth.test"


def test_rfc9207_without_issuer(test_client, server):
    """Without an issuer, the response has no iss parameter."""
    server.register_extension(_IssuerParameter())
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "iss=" not in rv.location
