import pytest

from authlib.oauth2.rfc6749.grants import ImplicitGrant

authorize_url = "/oauth/authorize?response_type=token&client_id=client-id"


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(ImplicitGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "response_types": ["token"],
            "grant_types": ["implicit"],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_get_authorize(test_client):
    rv = test_client.get(authorize_url)
    assert rv.data == b"login"


@pytest.mark.parametrize(
    "grant_types", [["implicit"], ["implicit", "authorization_code"]]
)
def test_confidential_client(test_client, db, client, grant_types):
    """Per RFC 6749 §3.2.1, the client does not authenticate at the
    authorization endpoint, so its token_endpoint_auth_method does not matter,
    and a client_secret parameter is ignored."""
    client.client_secret = "client-secret"
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "response_types": ["token"],
            "grant_types": grant_types,
            "token_endpoint_auth_method": "client_secret_basic",
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(authorize_url + "&user_id=1")
    assert rv.data == b"ok"

    rv = test_client.post(authorize_url + "&user_id=1&client_secret=client-secret")
    assert "access_token=" in rv.location


def test_unknown_client(test_client):
    """A missing or unknown client_id is refused without redirection."""
    rv = test_client.get("/oauth/authorize?response_type=token")
    assert rv.json["error"] == "invalid_client"
    assert rv.json["error_description"] == "Missing 'client_id' parameter."

    rv = test_client.get("/oauth/authorize?response_type=token&client_id=unknown")
    assert rv.json["error"] == "invalid_client"
    assert rv.json["error_description"] == "The client does not exist on this server."


def test_unsupported_client(test_client, db, client):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "response_types": ["code"],
            "grant_types": ["implicit"],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    rv = test_client.get(authorize_url + "&user_id=1")
    assert "unauthorized_client" in rv.location


def test_invalid_authorize(test_client, server):
    rv = test_client.post(authorize_url)
    assert "#error=access_denied" in rv.location

    server.scopes_supported = ["profile"]
    rv = test_client.post(authorize_url + "&scope=invalid&user_id=1")
    assert "#error=invalid_scope" in rv.location


def test_authorize_token(test_client):
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "access_token=" in rv.location

    url = authorize_url + "&state=bar&scope=profile"
    rv = test_client.post(url, data={"user_id": "1"})
    assert "access_token=" in rv.location
    assert "state=bar" in rv.location
    assert "scope=profile" in rv.location


def test_token_generator(test_client, app, server):
    m = "tests.flask.test_oauth2.oauth2_server:token_generator"
    app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
    server.load_config(app.config)
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "access_token=c-implicit.1." in rv.location


def test_missing_scope_uses_default(test_client, client, monkeypatch):
    """Per RFC 6749 Section 3.3, when scope is omitted, the server should use
    a pre-defined default value from client.get_allowed_scope().
    """

    def get_allowed_scope_with_default(scope):
        if scope is None:
            return "default_scope"
        return scope

    monkeypatch.setattr(client, "get_allowed_scope", get_allowed_scope_with_default)

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "access_token=" in rv.location
    assert "scope=default_scope" in rv.location


def test_missing_scope_empty_default(test_client, client, monkeypatch):
    """When client.get_allowed_scope() returns empty string for missing scope,
    the token should be issued without a scope.
    """

    def get_allowed_scope_empty(scope):
        if scope is None:
            return ""
        return scope

    monkeypatch.setattr(client, "get_allowed_scope", get_allowed_scope_empty)

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "access_token=" in rv.location
    assert "scope=" not in rv.location


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
    assert "#error=invalid_scope" in rv.location
