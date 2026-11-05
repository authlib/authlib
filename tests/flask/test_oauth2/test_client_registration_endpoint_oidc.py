import pytest
from flask import json

from authlib.oauth2.rfc7591 import ClientMetadataClaims as OAuth2ClientMetadataClaims
from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint as _ClientRegistrationEndpoint,
)
from authlib.oidc.backchannel import (
    ClientMetadataClaims as BackchannelClientMetadataClaims,
)
from authlib.oidc.registration import ClientMetadataClaims as OIDCClientMetadataClaims
from tests.util import read_file_path

from .models import Client
from .models import db


class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):
    software_statement_alg_values_supported = ["RS256"]

    def authenticate_token(self, request):
        auth_header = request.headers.get("Authorization")
        if auth_header:
            request.user_id = 1
            return auth_header

    def resolve_public_key(self, request):
        return read_file_path("rsa_public.pem")

    def save_client(self, client_info, client_metadata, request):
        client = Client(user_id=request.user_id, **client_info)
        client.set_client_metadata(client_metadata)
        db.session.add(client)
        db.session.commit()
        return client


@pytest.fixture
def metadata():
    return {}


@pytest.fixture(autouse=True)
def server(server, app, metadata):
    class MyClientRegistration(ClientRegistrationEndpoint):
        def get_server_metadata(self):
            return metadata

    server.register_endpoint(
        MyClientRegistration(
            claims_classes=[
                OAuth2ClientMetadataClaims,
                OIDCClientMetadataClaims,
                BackchannelClientMetadataClaims,
            ]
        )
    )

    @app.route("/create_client", methods=["POST"])
    def create_client():
        return server.create_endpoint_response("client_registration")

    return server


def test_application_type(test_client):
    # Nominal case
    body = {
        "application_type": "web",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["application_type"] == "web"

    # Default case
    # The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
    body = {
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["application_type"] == "web"

    # Error case
    body = {
        "application_type": "invalid",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_token_endpoint_auth_signing_alg_supported(test_client, metadata):
    metadata["token_endpoint_auth_signing_alg_values_supported"] = ["RS256", "ES256"]

    # Nominal case
    body = {
        "token_endpoint_auth_signing_alg": "ES256",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["token_endpoint_auth_signing_alg"] == "ES256"

    # Default case
    # The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
    body = {
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    # Error case
    body = {
        "token_endpoint_auth_signing_alg": "RS512",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_subject_types_supported(test_client, metadata):
    metadata["subject_types_supported"] = ["public", "pairwise"]

    # Nominal case
    body = {"subject_type": "public", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["subject_type"] == "public"

    # Error case
    body = {"subject_type": "invalid", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_id_token_signing_alg_values_supported(test_client, metadata):
    metadata["id_token_signing_alg_values_supported"] = ["RS256", "ES256"]

    # Default
    # The default, if omitted, is RS256.
    body = {"client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["id_token_signed_response_alg"] == "RS256"

    # Nominal case
    body = {"id_token_signed_response_alg": "ES256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["id_token_signed_response_alg"] == "ES256"

    # Error case
    body = {"id_token_signed_response_alg": "RS512", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata"


@pytest.mark.parametrize(
    "response_types",
    [None, ["code"], ["code", "token"], ["code token"]],
)
def test_id_token_signing_alg_values_none(test_client, metadata, response_types):
    """The none alg is accepted for clients that get no ID Token from the
    authorization endpoint."""
    metadata["id_token_signing_alg_values_supported"] = ["none", "RS256", "ES256"]
    body = {"id_token_signed_response_alg": "none", "client_name": "Authlib"}
    if response_types:
        body["response_types"] = response_types
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["id_token_signed_response_alg"] == "none"


@pytest.mark.parametrize(
    "response_types",
    [["id_token"], ["code", "id_token token"], ["code id_token"], ["token id_token"]],
)
def test_id_token_signing_alg_values_none_with_id_token(
    test_client, metadata, response_types
):
    """Per OpenID Connect Dynamic Client Registration §2, the none alg MUST NOT be
    used when the client gets an ID Token from the authorization endpoint."""
    metadata["id_token_signing_alg_values_supported"] = ["none", "RS256", "ES256"]
    body = {
        "id_token_signed_response_alg": "none",
        "client_name": "Authlib",
        "response_types": response_types,
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata"


def test_id_token_encryption_alg_values_supported(test_client, metadata):
    metadata["id_token_encryption_alg_values_supported"] = ["RS256", "ES256"]

    # Default case
    body = {"client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert "id_token_encrypted_response_enc" not in resp

    # If id_token_encrypted_response_alg is specified, the default
    # id_token_encrypted_response_enc value is A128CBC-HS256.
    body = {"id_token_encrypted_response_alg": "RS256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["id_token_encrypted_response_enc"] == "A128CBC-HS256"

    # Nominal case
    body = {"id_token_encrypted_response_alg": "ES256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["id_token_encrypted_response_alg"] == "ES256"

    # Error case
    body = {"id_token_encrypted_response_alg": "RS512", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_id_token_encryption_enc_values_supported(test_client, metadata):
    metadata["id_token_encryption_enc_values_supported"] = ["A128CBC-HS256", "A256GCM"]

    # Nominal case
    body = {
        "id_token_encrypted_response_alg": "RS256",
        "id_token_encrypted_response_enc": "A256GCM",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["id_token_encrypted_response_alg"] == "RS256"
    assert resp["id_token_encrypted_response_enc"] == "A256GCM"

    # Error case: missing id_token_encrypted_response_alg
    body = {"id_token_encrypted_response_enc": "A256GCM", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"

    # Error case: alg not in server metadata
    body = {"id_token_encrypted_response_enc": "A128GCM", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_userinfo_signing_alg_values_supported(test_client, metadata):
    metadata["userinfo_signing_alg_values_supported"] = ["RS256", "ES256"]

    # Nominal case
    body = {"userinfo_signed_response_alg": "ES256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["userinfo_signed_response_alg"] == "ES256"

    # Error case
    body = {"userinfo_signed_response_alg": "RS512", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_userinfo_encryption_alg_values_supported(test_client, metadata):
    metadata["userinfo_encryption_alg_values_supported"] = ["RS256", "ES256"]

    # Nominal case
    body = {"userinfo_encrypted_response_alg": "ES256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["userinfo_encrypted_response_alg"] == "ES256"

    # Error case
    body = {"userinfo_encrypted_response_alg": "RS512", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_userinfo_encryption_enc_values_supported(test_client, metadata):
    metadata["userinfo_encryption_enc_values_supported"] = ["A128CBC-HS256", "A256GCM"]

    # Default case
    body = {"client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert "userinfo_encrypted_response_enc" not in resp

    # If userinfo_encrypted_response_alg is specified, the default
    # userinfo_encrypted_response_enc value is A128CBC-HS256.
    body = {"userinfo_encrypted_response_alg": "RS256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["userinfo_encrypted_response_enc"] == "A128CBC-HS256"

    # Nominal case
    body = {
        "userinfo_encrypted_response_alg": "RS256",
        "userinfo_encrypted_response_enc": "A256GCM",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["userinfo_encrypted_response_alg"] == "RS256"
    assert resp["userinfo_encrypted_response_enc"] == "A256GCM"

    # Error case: no userinfo_encrypted_response_alg
    body = {"userinfo_encrypted_response_enc": "A256GCM", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"

    # Error case: alg not in server metadata
    body = {"userinfo_encrypted_response_enc": "A128GCM", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_acr_values_supported(test_client, metadata):
    metadata["acr_values_supported"] = [
        "urn:mace:incommon:iap:silver",
        "urn:mace:incommon:iap:bronze",
    ]

    # Nominal case
    body = {
        "default_acr_values": ["urn:mace:incommon:iap:silver"],
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["default_acr_values"] == ["urn:mace:incommon:iap:silver"]

    # Error case
    body = {
        "default_acr_values": [
            "urn:mace:incommon:iap:silver",
            "urn:mace:incommon:iap:gold",
        ],
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_request_object_signing_alg_values_supported(test_client, metadata):
    metadata["request_object_signing_alg_values_supported"] = ["RS256", "ES256"]

    # Nominal case
    body = {"request_object_signing_alg": "ES256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["request_object_signing_alg"] == "ES256"

    # Error case
    body = {"request_object_signing_alg": "RS512", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_request_object_encryption_alg_values_supported(test_client, metadata):
    metadata["request_object_encryption_alg_values_supported"] = ["RS256", "ES256"]

    # Nominal case
    body = {
        "request_object_encryption_alg": "ES256",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["request_object_encryption_alg"] == "ES256"

    # Error case
    body = {
        "request_object_encryption_alg": "RS512",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_request_object_encryption_enc_values_supported(test_client, metadata):
    metadata["request_object_encryption_enc_values_supported"] = [
        "A128CBC-HS256",
        "A256GCM",
    ]

    # Default case
    body = {"client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert "request_object_encryption_enc" not in resp

    # If request_object_encryption_alg is specified, the default
    # request_object_encryption_enc value is A128CBC-HS256.
    body = {"request_object_encryption_alg": "RS256", "client_name": "Authlib"}
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["request_object_encryption_enc"] == "A128CBC-HS256"

    # Nominal case
    body = {
        "request_object_encryption_alg": "RS256",
        "request_object_encryption_enc": "A256GCM",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["request_object_encryption_alg"] == "RS256"
    assert resp["request_object_encryption_enc"] == "A256GCM"

    # Error case: missing request_object_encryption_alg
    body = {
        "request_object_encryption_enc": "A256GCM",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"

    # Error case: alg not in server metadata
    body = {
        "request_object_encryption_enc": "A128GCM",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_require_auth_time(test_client):
    # Default case
    body = {
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["require_auth_time"] is False

    # Nominal case
    body = {
        "require_auth_time": True,
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["require_auth_time"] is True

    # Error case
    body = {
        "require_auth_time": "invalid",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_redirect_uri(test_client):
    """RFC6749 indicate that fragments are forbidden in redirect_uri.

        The redirection endpoint URI MUST be an absolute URI as defined by
        [RFC3986] Section 4.3.  [...]  The endpoint URI MUST NOT include a
        fragment component.

    https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2
    """
    # Nominal case
    body = {
        "redirect_uris": ["https://client.test"],
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["redirect_uris"] == ["https://client.test"]

    # Error case
    body = {
        "redirect_uris": ["https://client.test#fragment"],
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_backchannel_logout_uri(test_client, monkeypatch):
    """An http backchannel_logout_uri is an invalid_client_metadata error for public clients."""
    # Nominal case
    body = {
        "backchannel_logout_uri": "https://client.test/logout",
        "token_endpoint_auth_method": "none",
        "client_name": "Authlib",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["backchannel_logout_uri"] == "https://client.test/logout"

    # Error case
    body = {
        "backchannel_logout_uri": "http://client.test/logout",
        "token_endpoint_auth_method": "none",
        "client_name": "Authlib",
    }
    with monkeypatch.context() as m:
        m.delenv("AUTHLIB_INSECURE_TRANSPORT")
        rv = test_client.post(
            "/create_client", json=body, headers={"Authorization": "bearer abc"}
        )
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata"


@pytest.mark.parametrize(
    "client_metadata",
    [
        {"default_acr_values": 5},
        {"default_acr_values": [{"acr": "1"}]},
        {"default_max_age": "60"},
        {"response_types": [5], "id_token_signed_response_alg": "none"},
        {"default_max_age": True},
        {"require_auth_time": "true"},
        {"request_uris": "https://client.test/request"},
        {"id_token_signed_response_alg": ["RS256"]},
        {"backchannel_logout_session_required": "true"},
    ],
)
@pytest.mark.parametrize("with_metadata", [True, False])
def test_invalid_metadata_type(test_client, metadata, client_metadata, with_metadata):
    """OpenID Connect client metadata with an unexpected type is refused."""
    if with_metadata:
        metadata["acr_values_supported"] = ["urn:mace:incommon:iap:silver"]

    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib", **client_metadata}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_client_metadata"


def test_default_max_age_float(test_client):
    """default_max_age is a JSON number, so a float is accepted."""
    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib", "default_max_age": 3600.0}
    rv = test_client.post("/create_client", json=body, headers=headers)
    assert rv.status_code == 201


def test_null_response_types(test_client):
    """A null response_types is ignored by the OpenID Connect checks."""
    headers = {"Authorization": "bearer abc"}
    body = {
        "client_name": "Authlib",
        "response_types": None,
        "id_token_signed_response_alg": "none",
    }
    rv = test_client.post("/create_client", json=body, headers=headers)
    assert rv.status_code == 201
