import pytest
from flask import json

from authlib.oauth2.rfc7591 import ClientMetadataClaims as OAuth2ClientMetadataClaims
from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint as _ClientRegistrationEndpoint,
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
            claims_classes=[OAuth2ClientMetadataClaims, OIDCClientMetadataClaims]
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


def test_id_token_signing_alg_values_none(test_client, metadata):
    # The value none MUST NOT be used as the ID Token alg value unless the Client uses
    # only Response Types that return no ID Token from the Authorization Endpoint
    # (such as when only using the Authorization Code Flow).
    metadata["id_token_signing_alg_values_supported"] = ["none", "RS256", "ES256"]

    # Nominal case
    body = {
        "id_token_signed_response_alg": "none",
        "client_name": "Authlib",
        "response_type": "code",
    }
    rv = test_client.post(
        "/create_client", json=body, headers={"Authorization": "bearer abc"}
    )
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert resp["id_token_signed_response_alg"] == "none"

    # Error case
    body = {
        "id_token_signed_response_alg": "none",
        "client_name": "Authlib",
        "response_type": "id_token",
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
