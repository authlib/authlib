import time

import pytest
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc9470 import StepUpAuthentication

from .models import AuthorizationCode
from .models import AuthorizationSession
from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id"


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


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    return server


def test_get_authorize(test_client):
    rv = test_client.get(authorize_url)
    assert rv.data == b"login"


def test_invalid_client_id(test_client):
    url = "/oauth/authorize?response_type=code"
    rv = test_client.get(url)
    assert b"invalid_client" in rv.data

    url = "/oauth/authorize?response_type=code&client_id=invalid"
    rv = test_client.get(url)
    assert b"invalid_client" in rv.data


def test_invalid_authorize(test_client, server):
    rv = test_client.post(authorize_url)
    assert "error=access_denied" in rv.location

    server.scopes_supported = ["profile"]
    rv = test_client.post(authorize_url + "&scope=invalid&state=foo&user_id=1")
    assert "error=invalid_scope" in rv.location
    assert "state=foo" in rv.location


def test_unauthorized_client(test_client, client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["token"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(authorize_url + "&user_id=1")
    assert "unauthorized_client" in rv.location


def test_invalid_client(test_client):
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "invalid",
            "client_id": "invalid-id",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    headers = create_basic_header("code-client", "invalid-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "invalid",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"
    assert resp["error_uri"] == "https://client.test/error#invalid_client"


def test_invalid_code(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "invalid",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"

    code = AuthorizationCode(code="no-user", client_id="code-client", user_id=0)
    db.session.add(code)
    db.session.commit()
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "no-user",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_invalid_redirect_uri(test_client):
    uri = authorize_url + "&redirect_uri=https%3A%2F%2Fa.c"
    rv = test_client.post(uri, data={"user_id": "1"})
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    uri = authorize_url + "&redirect_uri=https%3A%2F%2Fclient.test"
    rv = test_client.post(uri, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_invalid_grant_type(test_client, client, db):
    client.client_secret = ""
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["invalid"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client-id",
            "code": "a",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_authorize_token_no_refresh_token(app, test_client, client, db, server):
    app.config.update({"OAUTH2_REFRESH_TOKEN_GENERATOR": True})
    server.load_config(app.config)
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "refresh_token" not in resp


def test_authorize_token_has_refresh_token(app, test_client, client, db, server):
    app.config.update({"OAUTH2_REFRESH_TOKEN_GENERATOR": True})
    server.load_config(app.config)
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()

    url = authorize_url + "&state=bar"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "bar"

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "refresh_token" in resp


def test_invalid_multiple_request_parameters(test_client):
    url = (
        authorize_url
        + "&scope=profile&state=bar&redirect_uri=https%3A%2F%2Fclient.test&response_type=code"
    )
    rv = test_client.get(url)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert resp["error_description"] == "Multiple 'response_type' in request."


def test_repeated_undeclared_parameter(test_client):
    """A parameter that no grant or extension declares can be repeated."""
    rv = test_client.get(authorize_url + "&foo=bar&foo=baz")
    assert rv.data == b"login"


def get_authorization_key(app, server, url, method="GET", data=None):
    """Return the authorization key of a request to the authorization
    endpoint."""
    with app.test_request_context(url, method=method, data=data):
        grant = server.get_consent_grant()

    return grant.request.authorization_key


def test_authorization_key(app, server):
    """The authorization key is the same for the HTTP requests of one
    authorization request."""
    url = authorize_url + "&scope=profile&state=bar"
    key = get_authorization_key(app, server, url)

    assert get_authorization_key(app, server, url + "&foo=bar") == key
    assert get_authorization_key(app, server, url, "POST", {"user_id": "1"}) == key
    assert (
        get_authorization_key(
            app,
            server,
            "/oauth/authorize",
            "POST",
            {
                "state": "bar",
                "scope": "profile",
                "client_id": "client-id",
                "response_type": "code",
            },
        )
        == key
    )


def test_authorization_key_differs(app, server):
    """Two authorization requests with different parameters have different
    authorization keys."""
    key = get_authorization_key(app, server, authorize_url + "&state=bar")
    assert get_authorization_key(app, server, authorize_url + "&state=baz") != key


def test_client_secret_post(app, test_client, client, db, server):
    app.config.update({"OAUTH2_REFRESH_TOKEN_GENERATOR": True})
    server.load_config(app.config)
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()

    url = authorize_url + "&state=bar"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "bar"

    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "code": code,
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "refresh_token" in resp


def test_token_generator(app, test_client, client, server):
    m = "tests.flask.test_oauth2.oauth2_server:token_generator"
    app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
    server.load_config(app.config)
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "c-authorization_code.1." in resp["access_token"]


def test_missing_scope_uses_default(test_client, client, monkeypatch):
    """Per RFC 6749 Section 3.3, when scope is omitted at authorization endpoint,
    the server should use a pre-defined default value from client.get_allowed_scope().
    """

    def get_allowed_scope_with_default(scope):
        if scope is None:
            return "default_scope"
        return scope

    monkeypatch.setattr(client, "get_allowed_scope", get_allowed_scope_with_default)

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert resp.get("scope") == "default_scope"


def test_missing_scope_empty_default(test_client, client, monkeypatch):
    """When client.get_allowed_scope() returns empty string for missing scope,
    the authorization should proceed without a scope.
    """

    def get_allowed_scope_empty(scope):
        if scope is None:
            return ""
        return scope

    monkeypatch.setattr(client, "get_allowed_scope", get_allowed_scope_empty)

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert resp.get("scope", "") == ""


def test_missing_scope_rejected(test_client, client, monkeypatch):
    """Per RFC 6749 Section 3.3, when scope is omitted and client.get_allowed_scope()
    returns None, the authorization should fail with invalid_scope.
    """

    def get_allowed_scope_reject(scope):
        if scope is None:
            return None
        return scope

    monkeypatch.setattr(client, "get_allowed_scope", get_allowed_scope_reject)

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "error=invalid_scope" in rv.location


def test_create_authorization_response_requires_grant(server):
    """The authorization response needs the grant of the consent page."""
    with pytest.raises(TypeError, match="get_consent_grant"):
        server.create_authorization_response(grant_user=None)


def test_session_user_mismatch(app, server, monkeypatch):
    """The end user and the user of the authorization session must be the
    same. The request still ends when the granted user differs."""
    ended = []
    monkeypatch.setattr(
        AuthorizationSession, "end_request", lambda self, request: ended.append(1)
    )
    session = AuthorizationSession(db.session.get(User, 1))
    with app.test_request_context(authorize_url):
        with pytest.raises(ValueError, match="end_user"):
            server.get_consent_grant(end_user=object(), session=session)

        grant = server.get_consent_grant(session=session)
        with pytest.raises(ValueError, match="grant_user"):
            server.create_authorization_response(grant=grant, grant_user=object())

    assert ended == [1]


@pytest.mark.parametrize("user_id", ["1", ""])
def test_end_request(test_client, monkeypatch, user_id):
    """The authorization session is told when the request ends, when the
    user accepts or denies it, and on errors."""
    keys = []
    monkeypatch.setattr(
        AuthorizationSession,
        "end_request",
        lambda self, request: keys.append(request.authorization_key),
    )
    test_client.get(authorize_url)
    assert keys == []

    test_client.post(authorize_url, data={"user_id": user_id})
    assert len(keys) == 1
    assert keys[0]

    test_client.get("/oauth/authorize?response_type=foo&client_id=client-id")
    assert len(keys) == 2
    assert keys[1] is None


def test_consent_needed(test_client, monkeypatch):
    """When the authorization session needs a consent, consent is an
    interaction of the request. An anonymous user must log in first."""
    monkeypatch.setattr(
        AuthorizationSession, "is_consent_needed", lambda self, request: True
    )
    rv = test_client.get(authorize_url + "&user_id=1")
    assert rv.data == b"consent"

    rv = test_client.get(authorize_url)
    assert rv.data == b"login"


def test_step_up_authentication(test_client, server):
    """StepUpAuthentication applies max_age to the OAuth requests."""
    server.register_extension(StepUpAuthentication())
    old = int(time.time()) - 7200
    rv = test_client.get(authorize_url + f"&user_id=1&max_age=60&auth_time={old}")
    assert rv.data == b"login"

    rv = test_client.get(
        authorize_url + f"&user_id=1&max_age=60&auth_time={old + 7200}"
    )
    assert rv.data == b"ok"


def test_end_request_on_any_error(test_client, monkeypatch):
    """The authorization session is told when the request ends, also on an
    unexpected error."""
    ended = []
    monkeypatch.setattr(
        AuthorizationSession, "end_request", lambda self, request: ended.append(1)
    )

    def is_consent_needed(self, request):
        raise RuntimeError("database down")

    monkeypatch.setattr(AuthorizationSession, "is_consent_needed", is_consent_needed)
    with pytest.raises(RuntimeError):
        test_client.get(authorize_url + "&user_id=1")

    assert ended == [1]


def test_login_after_create(app, server, monkeypatch):
    """The login of an anonymous user comes after the "create" interaction."""

    def validate_consent_request(self):
        self.interactions.append("create")

    monkeypatch.setattr(
        AuthorizationCodeGrant, "validate_consent_request", validate_consent_request
    )
    with app.test_request_context(authorize_url):
        grant = server.get_consent_grant()

    assert grant.interactions == ["create", "login"]


def test_insecure_transport_on_authorization_response(app, server, monkeypatch):
    """create_authorization_response returns an insecure_transport error for
    a plain HTTP request."""
    user = db.session.get(User, 1)
    with app.test_request_context(authorize_url, base_url="https://auth.test"):
        grant = server.get_consent_grant(end_user=user)

    with monkeypatch.context() as m:
        m.delenv("AUTHLIB_INSECURE_TRANSPORT")
        with app.test_request_context(
            authorize_url, method="POST", base_url="http://auth.test"
        ):
            rv = server.create_authorization_response(grant=grant, grant_user=user)

    assert rv.status_code == 400
    assert rv.json["error"] == "insecure_transport"
