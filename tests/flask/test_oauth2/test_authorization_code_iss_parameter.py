import pytest

from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc9207 import IssuerParameter as _IssuerParameter

from .models import CodeGrantMixin
from .models import save_authorization_code

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
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
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
