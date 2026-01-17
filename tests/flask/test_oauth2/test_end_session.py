import pytest

from authlib.oidc.rpinitiated import EndSessionEndpoint
from tests.util import read_file_path

from .conftest import create_id_token
from .models import Client
from .models import db


class FlaskEndSessionEndpoint(EndSessionEndpoint):
    def __init__(self, issuer="https://provider.test"):
        super().__init__()
        self.issuer = issuer

    def get_client_by_id(self, client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def get_server_jwks(self):
        return read_file_path("jwks_public.json")

    def validate_id_token_claims(self, id_token_claims):
        if id_token_claims is None:
            return False
        return id_token_claims.get("iss") == self.issuer

    def end_session(self, request, id_token_claims):
        pass

    def create_end_session_response(self, request):
        return 200, "Logged out", [("Content-Type", "text/plain")]

    def create_confirmation_response(self, request, client, redirect_uri, ui_locales):
        return 200, "Confirm logout", [("Content-Type", "text/plain")]


class ConfirmingEndSessionEndpoint(FlaskEndSessionEndpoint):
    """Endpoint that auto-confirms post logout redirection without id_token_hint."""

    def is_post_logout_redirect_uri_legitimate(
        self, request, post_logout_redirect_uri, client, logout_hint
    ):
        return True


@pytest.fixture
def confirming_server(server, app, db):
    endpoint = ConfirmingEndSessionEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session", methods=["GET", "POST"])
    def end_session():
        return server.create_endpoint_response("end_session")

    return server


@pytest.fixture
def base_server(server, app, db):
    endpoint = FlaskEndSessionEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session_base", methods=["GET", "POST"])
    def end_session_base():
        return server.create_endpoint_response("end_session")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "post_logout_redirect_uris": [
                "https://client.test/logout",
                "https://client.test/logged-out",
            ],
            "scope": "openid profile",
        }
    )
    db.session.add(client)
    db.session.commit()

    return client


def test_end_session_with_valid_id_token(
    test_client, confirming_server, client, id_token
):
    """Logout with valid id_token_hint should succeed."""
    rv = test_client.get(f"/oauth/end_session?id_token_hint={id_token}")

    assert rv.status_code == 200
    assert rv.data == b"Logged out"


def test_end_session_with_redirect_uri(
    test_client, confirming_server, client, id_token
):
    """Logout with valid redirect URI should redirect."""
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout"


def test_end_session_with_redirect_uri_and_state(
    test_client, confirming_server, client, id_token
):
    """State parameter should be appended to redirect URI."""
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
        "&state=xyz123"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout?state=xyz123"


def test_end_session_invalid_redirect_uri(test_client, base_server, client, id_token):
    """Unregistered redirect URI should result in no redirection."""
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://attacker.test/logout"
    )

    assert rv.status_code == 200


def test_end_session_redirect_without_id_token(test_client, confirming_server, client):
    """Redirect URI without id_token_hint asks user for confirmation."""
    rv = test_client.get(
        "/oauth/end_session?client_id=client-id"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 200
    assert rv.data == b"Confirm logout"


def test_end_session_client_id_mismatch(
    test_client, confirming_server, client, id_token
):
    """client_id not matching aud claim should return error."""
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token}&client_id=other-client"
    )

    assert rv.status_code == 400


def test_end_session_post_with_form_data(
    test_client, confirming_server, client, id_token
):
    """End session should support POST with form-encoded data."""
    rv = test_client.post(
        "/oauth/end_session",
        data={
            "id_token_hint": id_token,
            "post_logout_redirect_uri": "https://client.test/logout",
            "state": "abc",
        },
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout?state=abc"


def test_no_id_token_requires_confirmation(test_client, base_server, client):
    """Logout without id_token_hint should show confirmation page."""
    rv = test_client.get("/oauth/end_session_base")

    assert rv.status_code == 200
    assert rv.data == b"Confirm logout"


def test_redirect_without_id_token_requires_confirmation(
    test_client, base_server, client
):
    """Redirect URI without id_token_hint should show confirmation without redirect."""
    rv = test_client.get(
        "/oauth/end_session_base?client_id=client-id"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 200
    assert rv.data == b"Confirm logout"


def test_invalid_id_token_requires_confirmation(
    test_client, base_server, client, id_token_wrong_issuer
):
    """Invalid id_token_hint should show confirmation page."""
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token_wrong_issuer}"
    )

    assert rv.status_code == 400
    assert rv.json == {
        "error": "invalid_request",
        "error_description": "Invalid id_token_hint",
    }


def test_valid_id_token_succeeds_without_confirmation(
    test_client, base_server, client, id_token
):
    """Valid id_token_hint should succeed without confirmation."""
    rv = test_client.get(f"/oauth/end_session_base?id_token_hint={id_token}")

    assert rv.status_code == 200
    assert rv.data == b"Logged out"


def test_valid_id_token_with_redirect_succeeds_without_confirmation(
    test_client, base_server, client, id_token
):
    """Valid id_token_hint with redirect URI should succeed."""
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token}"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 302
    assert rv.headers["Location"] == "https://client.test/logout"


def test_client_id_matches_aud_list(test_client, confirming_server, client):
    """client_id should match when aud is a list containing it."""
    id_token_with_aud_list = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": ["client-id", "other-client"],
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token_with_aud_list}&client_id=client-id"
    )

    assert rv.status_code == 200
    assert rv.data == b"Logged out"


def test_client_id_mismatch_with_aud_list(test_client, confirming_server, client):
    """client_id not in aud list should return error."""
    id_token_with_aud_list = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": ["other-client-1", "other-client-2"],
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )
    rv = test_client.get(
        f"/oauth/end_session?id_token_hint={id_token_with_aud_list}&client_id=client-id"
    )

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert rv.json["error_description"] == "'client_id' does not match 'aud' claim"


def test_invalid_jwt(test_client, confirming_server, client):
    """Invalid JWT should return error."""
    rv = test_client.get("/oauth/end_session?id_token_hint=invalid.jwt.token")

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"


def test_resolve_client_from_aud_list_returns_none(test_client, base_server, client):
    """When aud is a list, resolve_client_from_id_token_claims returns None by default."""
    id_token_with_aud_list = create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": ["client-id", "other-client"],
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )
    # Without client_id parameter, client resolution from aud list returns None
    # and redirect_uri validation fails (no client), so no redirect happens
    rv = test_client.get(
        f"/oauth/end_session_base?id_token_hint={id_token_with_aud_list}"
        "&post_logout_redirect_uri=https://client.test/logout"
    )

    assert rv.status_code == 200
    assert rv.data == b"Logged out"


class DefaultConfirmationEndpoint(EndSessionEndpoint):
    """Endpoint using default create_confirmation_response."""

    def get_client_by_id(self, client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def get_server_jwks(self):
        return read_file_path("jwks_public.json")

    def end_session(self, request, id_token_claims):
        pass

    def create_end_session_response(self, request):
        return 200, "Logged out", [("Content-Type", "text/plain")]


@pytest.fixture
def default_confirmation_server(server, app, db):
    endpoint = DefaultConfirmationEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session_default_confirm", methods=["GET", "POST"])
    def end_session_default_confirm():
        return server.create_endpoint_response("end_session")

    return server


def test_default_create_confirmation_response(
    test_client, default_confirmation_server, client
):
    """Default create_confirmation_response should return 400 error."""
    rv = test_client.get("/oauth/end_session_default_confirm")

    assert rv.status_code == 400
    assert rv.data == b"Logout confirmation required"


class DefaultValidationEndpoint(EndSessionEndpoint):
    """Endpoint using default validate_id_token_claims."""

    def get_client_by_id(self, client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def get_server_jwks(self):
        return read_file_path("jwks_public.json")

    def end_session(self, request, id_token_claims):
        pass

    def create_end_session_response(self, request):
        return 200, "Logged out", [("Content-Type", "text/plain")]

    def create_confirmation_response(self, request, client, redirect_uri, ui_locales):
        return 200, "Confirm logout", [("Content-Type", "text/plain")]


@pytest.fixture
def default_validation_server(server, app, db):
    endpoint = DefaultValidationEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/oauth/end_session_default_validation", methods=["GET", "POST"])
    def end_session_default_validation():
        return server.create_endpoint_response("end_session")

    return server


def test_default_validate_id_token_claims(
    test_client, default_validation_server, client, id_token
):
    """Default validate_id_token_claims should accept any valid JWT."""
    rv = test_client.get(
        f"/oauth/end_session_default_validation?id_token_hint={id_token}"
    )

    assert rv.status_code == 200
    assert rv.data == b"Logged out"
