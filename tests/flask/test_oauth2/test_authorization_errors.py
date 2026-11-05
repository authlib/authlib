"""Per RFC 9700 §4.11.2, the server authenticates the user before it
redirects them, and only redirects them to a redirect URI it trusts."""

import pytest
from flask import session

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

from .models import AuthorizationCode
from .models import AuthorizationSession
from .models import CodeGrantMixin
from .models import StoredAuthorizationSession
from .models import User
from .models import db
from .models import save_authorization_code

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id&state=bar"


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    server.scopes_supported = ["profile", "address"]
    return server


class UntrustedAuthorizationSession(AuthorizationSession):
    """An authorization session that does not trust the redirect URIs."""

    calls = []

    def can_redirect_error(self, request, error):
        self.calls.append((request.client.client_id, error.error))
        return False


def query_params(rv):
    return dict(url_decode(urlparse.urlparse(rv.location).query))


@pytest.mark.parametrize(
    "authorization_session", [AuthorizationSession, None], indirect=True
)
def test_error_after_login(test_client, authorization_session):
    """The error of an anonymous user is redirected after the login."""
    rv = test_client.get(authorize_url + "&scope=invalid")
    assert rv.data == b"login"

    rv = test_client.get(authorize_url + "&scope=invalid&user_id=1")
    params = query_params(rv)
    assert params["error"] == "invalid_scope"
    assert params["state"] == "bar"


@pytest.mark.parametrize(
    "authorization_session", [AuthorizationSession, None], indirect=True
)
def test_no_redirection_before_login(test_client, authorization_session):
    """When an anonymous user submits the consent form, the error is
    returned without redirection."""
    rv = test_client.post(authorize_url + "&scope=invalid")
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_scope"
    assert rv.json["state"] == "bar"


@pytest.mark.parametrize("authorization_session", [None], indirect=True)
def test_no_code_for_deferred_grant(app, server, authorization_session):
    """The grant of an anonymous user never gives a code, even if the
    application passes a user to create_authorization_response."""
    user = db.session.get(User, 1)
    with app.test_request_context(authorize_url + "&scope=invalid"):
        grant = server.get_consent_grant()
        assert grant.interactions == ["login"]
        rv = server.create_authorization_response(grant=grant, grant_user=user)

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_scope"
    assert db.session.query(AuthorizationCode).count() == 0


def test_unsupported_response_type(test_client):
    """Without a grant, the error of an anonymous user is not redirected."""
    url = "/oauth/authorize?response_type=unknown&client_id=client-id"
    rv = test_client.get(url)
    assert rv.status_code == 400
    assert rv.json["error"] == "unsupported_response_type"

    rv = test_client.get(url + "&user_id=1")
    assert query_params(rv)["error"] == "unsupported_response_type"


def test_defer_anonymous_errors_disabled(test_client, server):
    """With defer_anonymous_errors disabled, the error of an anonymous user
    is redirected at once."""
    server.defer_anonymous_errors = False
    rv = test_client.get(authorize_url + "&scope=invalid")
    assert query_params(rv)["error"] == "invalid_scope"


@pytest.mark.parametrize(
    "authorization_session", [UntrustedAuthorizationSession], indirect=True
)
@pytest.mark.parametrize(
    "method,url,error",
    [
        ("GET", authorize_url + "&scope=invalid&user_id=1", "invalid_scope"),
        ("POST", authorize_url + "&scope=invalid&user_id=1", "invalid_scope"),
        (
            "GET",
            "/oauth/authorize?response_type=unknown&client_id=client-id&user_id=1",
            "unsupported_response_type",
        ),
        ("POST", authorize_url, "access_denied"),
    ],
)
def test_untrusted_redirect_uri(test_client, authorization_session, method, url, error):
    """When the authorization session does not trust the redirect URI, the
    error is returned without redirection."""
    authorization_session.calls.clear()
    rv = test_client.open(url, method=method)
    assert rv.status_code == 400
    assert rv.json["error"] == error
    assert authorization_session.calls == [("client-id", error)]


def test_deferred_grant_keeps_request_time(app, server):
    """The start time of the request is kept until the login, and the
    request ends once."""
    ended = []

    class Session(StoredAuthorizationSession):
        def end_request(self, request):
            ended.append(request.authorization_key)
            super().end_request(request)

    with app.test_request_context(authorize_url + "&scope=invalid"):
        grant = server.get_consent_grant(session=Session(None))
        key = grant.request.authorization_key
        assert key in session["authlib_request_times"]

        server.create_authorization_response(grant=grant)
        assert ended == [key]
