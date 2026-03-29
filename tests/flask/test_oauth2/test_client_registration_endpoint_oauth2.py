import pytest
from flask import json
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint as _ClientRegistrationEndpoint,
)
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
        def get_server_metadata(test_client):
            return metadata

    server.register_endpoint(MyClientRegistration)

    @app.route("/create_client", methods=["POST"])
    def create_client():
        return server.create_endpoint_response("client_registration")

    return server


def test_access_denied(test_client):
    rv = test_client.post("/create_client", json={})
    resp = json.loads(rv.data)
    assert resp["error"] == "access_denied"


def test_invalid_request(test_client):
    headers = {"Authorization": "bearer abc"}
    rv = test_client.post("/create_client", json={}, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_create_client(test_client):
    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"


def test_software_statement(test_client):
    payload = {"software_id": "uuid-123", "client_name": "Authlib"}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    software_statement = jwt.encode({"alg": "RS256"}, payload, key)
    body = {
        "software_statement": software_statement,
    }

    headers = {"Authorization": "bearer abc"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"


def test_no_public_key(test_client, server):
    class ClientRegistrationEndpoint2(ClientRegistrationEndpoint):
        def get_server_metadata(test_client):
            return None

        def resolve_public_key(self, request):
            return None

    payload = {"software_id": "uuid-123", "client_name": "Authlib"}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    software_statement = jwt.encode({"alg": "RS256"}, payload, key)
    body = {
        "software_statement": software_statement,
    }

    server._endpoints[ClientRegistrationEndpoint.ENDPOINT_NAME] = [
        ClientRegistrationEndpoint2(server)
    ]

    headers = {"Authorization": "bearer abc"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "unapproved_software_statement"


def test_scopes_supported(test_client, metadata):
    metadata["scopes_supported"] = ["profile", "email"]

    headers = {"Authorization": "bearer abc"}
    body = {"scope": "profile email", "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    body = {"scope": "profile email address", "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_response_types_supported(test_client, metadata):
    metadata["response_types_supported"] = ["code", "code id_token"]

    headers = {"Authorization": "bearer abc"}
    body = {"response_types": ["code"], "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    # The items order should not matter
    # Extension response types MAY contain a space-delimited (%x20) list of
    # values, where the order of values does not matter (e.g., response
    # type "a b" is the same as "b a").
    headers = {"Authorization": "bearer abc"}
    body = {"response_types": ["id_token code"], "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    # https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    # If omitted, the default is that the client will use only the "code"
    # response type.
    body = {"client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    body = {"response_types": ["code", "token"], "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_grant_types_supported(test_client, metadata):
    metadata["grant_types_supported"] = ["authorization_code", "password"]

    headers = {"Authorization": "bearer abc"}
    body = {"grant_types": ["password"], "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    # https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    # If omitted, the default behavior is that the client will use only
    # the "authorization_code" Grant Type.
    body = {"client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    body = {"grant_types": ["client_credentials"], "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_token_endpoint_auth_methods_supported(test_client, metadata):
    metadata["token_endpoint_auth_methods_supported"] = ["client_secret_basic"]

    headers = {"Authorization": "bearer abc"}
    body = {
        "token_endpoint_auth_method": "client_secret_basic",
        "client_name": "Authlib",
    }
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"

    body = {"token_endpoint_auth_method": "none", "client_name": "Authlib"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_validate_contacts(test_client):
    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib", "contacts": "invalid"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "contacts" in resp["error_description"]


def test_validate_jwks(test_client):
    headers = {"Authorization": "bearer abc"}

    keyset = KeySet.generate_key_set("oct", 128, count=1)
    valid_jwks = keyset.as_dict()

    body = {"client_name": "Authlib", "jwks": valid_jwks}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_name"] == "Authlib"

    # case 1: jwks and jwks_uri both provided
    body = {
        "client_name": "Authlib",
        "jwks": valid_jwks,
        "jwks_uri": "http://testserver/jwks",
    }
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "jwks" in resp["error_description"]

    # case 2: empty jwks
    body = {"client_name": "Authlib", "jwks": {"keys": []}}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "jwks" in resp["error_description"]

    # case 3: invalid jwks
    body = {"client_name": "Authlib", "jwks": {"keys": "hello"}}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "jwks" in resp["error_description"]
