import pytest
from flask import json

from authlib.oauth2.rfc7592 import (
    ClientConfigurationEndpoint as _ClientConfigurationEndpoint,
)

from .models import Client
from .models import Token
from .models import db


class ClientConfigurationEndpoint(_ClientConfigurationEndpoint):
    software_statement_alg_values_supported = ["RS256"]

    def authenticate_token(self, request):
        auth_header = request.headers.get("Authorization")
        if auth_header:
            access_token = auth_header.split()[1]
            return Token.query.filter_by(access_token=access_token).first()

    def update_client(self, client, client_metadata, request):
        client.set_client_metadata(client_metadata)
        db.session.add(client)
        db.session.commit()
        return client

    def authenticate_client(self, request):
        client_id = request.uri.split("/")[-1]
        return Client.query.filter_by(client_id=client_id).first()

    def revoke_access_token(self, request, token):
        token.revoked = True
        db.session.add(token)
        db.session.commit()

    def check_permission(self, client, request):
        client_id = request.uri.split("/")[-1]
        return client_id != "unauthorized_client_id"

    def delete_client(self, client, request):
        db.session.delete(client)
        db.session.commit()

    def generate_client_registration_info(self, client, request):
        return {
            "registration_client_uri": request.uri,
            "registration_access_token": request.headers["Authorization"].split(" ")[1],
        }


@pytest.fixture
def metadata():
    return {}


@pytest.fixture(autouse=True)
def server(server, app, metadata):
    @app.route("/configure_client/<client_id>", methods=["PUT", "GET", "DELETE"])
    def configure_client(client_id):
        return server.create_endpoint_response(
            ClientConfigurationEndpoint.ENDPOINT_NAME
        )

    class MyClientConfiguration(ClientConfigurationEndpoint):
        def get_server_metadata(test_client):
            return metadata

    server.register_endpoint(MyClientConfiguration)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "client_name": "Authlib",
            "scope": "openid profile",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_read_client(test_client, client, token):
    assert client.client_name == "Authlib"
    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.get("/configure_client/client-id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 200
    assert resp["client_id"] == client.client_id
    assert resp["client_name"] == "Authlib"
    assert (
        resp["registration_client_uri"] == "http://localhost/configure_client/client-id"
    )
    assert resp["registration_access_token"] == token.access_token


def test_read_access_denied(test_client):
    rv = test_client.get("/configure_client/client-id")
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"

    headers = {"Authorization": "bearer invalid_token"}
    rv = test_client.get("/configure_client/client-id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"

    headers = {"Authorization": "bearer unauthorized_token"}
    rv = test_client.get(
        "/configure_client/client-id",
        json={"client_id": "client-id", "client_name": "new client_name"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"


def test_read_invalid_client(test_client, token):
    # If the client does not exist on this server, the server MUST respond
    # with HTTP 401 Unauthorized, and the registration access token used to
    # make this request SHOULD be immediately revoked.

    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.get("/configure_client/invalid_client_id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 401
    assert resp["error"] == "invalid_client"


def test_read_unauthorized_client(test_client, token):
    # If the client does not have permission to read its record, the server
    # MUST return an HTTP 403 Forbidden.

    client = Client(
        client_id="unauthorized_client_id",
        client_secret="unauthorized_client_secret",
    )
    db.session.add(client)

    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.get("/configure_client/unauthorized_client_id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 403
    assert resp["error"] == "unauthorized_client"


def test_update_client(test_client, client, token):
    # Valid values of client metadata fields in this request MUST replace,
    # not augment, the values previously associated with this client.
    # Omitted fields MUST be treated as null or empty values by the server,
    # indicating the client's request to delete them from the client's
    # registration.  The authorization server MAY ignore any null or empty
    # value in the request just as any other value.

    assert client.client_name == "Authlib"
    headers = {"Authorization": f"bearer {token.access_token}"}
    body = {
        "client_id": client.client_id,
        "client_name": "NewAuthlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 200
    assert resp["client_id"] == client.client_id
    assert resp["client_name"] == "NewAuthlib"
    assert client.client_name == "NewAuthlib"
    assert client.scope == ""


def test_update_access_denied(test_client):
    rv = test_client.put("/configure_client/client-id", json={})
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"

    headers = {"Authorization": "bearer invalid_token"}
    rv = test_client.put("/configure_client/client-id", json={}, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"

    headers = {"Authorization": "bearer unauthorized_token"}
    rv = test_client.put(
        "/configure_client/client-id",
        json={"client_id": "client-id", "client_name": "new client_name"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"


def test_update_invalid_request(test_client, token):
    headers = {"Authorization": f"bearer {token.access_token}"}

    # The client MUST include its 'client_id' field in the request...
    rv = test_client.put("/configure_client/client-id", json={}, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_request"

    # ... and it MUST be the same as its currently issued client identifier.
    rv = test_client.put(
        "/configure_client/client-id",
        json={"client_id": "invalid_client_id"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_request"

    # The updated client metadata fields request MUST NOT include the
    # 'registration_access_token', 'registration_client_uri',
    # 'client_secret_expires_at', or 'client_id_issued_at' fields
    rv = test_client.put(
        "/configure_client/client-id",
        json={
            "client_id": "client-id",
            "registration_client_uri": "https://client.test",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_request"

    # If the client includes the 'client_secret' field in the request,
    # the value of this field MUST match the currently issued client
    # secret for that client.
    rv = test_client.put(
        "/configure_client/client-id",
        json={"client_id": "client-id", "client_secret": "invalid_secret"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_request"


def test_update_invalid_client(test_client, token):
    # If the client does not exist on this server, the server MUST respond
    # with HTTP 401 Unauthorized, and the registration access token used to
    # make this request SHOULD be immediately revoked.

    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.put(
        "/configure_client/invalid_client_id",
        json={"client_id": "invalid_client_id", "client_name": "new client_name"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 401
    assert resp["error"] == "invalid_client"


def test_update_unauthorized_client(test_client, token):
    # If the client does not have permission to read its record, the server
    # MUST return an HTTP 403 Forbidden.

    client = Client(
        client_id="unauthorized_client_id",
        client_secret="unauthorized_client_secret",
    )
    db.session.add(client)

    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.put(
        "/configure_client/unauthorized_client_id",
        json={
            "client_id": "unauthorized_client_id",
            "client_name": "new client_name",
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 403
    assert resp["error"] == "unauthorized_client"


def test_update_invalid_metadata(test_client, metadata, client, token):
    metadata["token_endpoint_auth_methods_supported"] = ["client_secret_basic"]
    headers = {"Authorization": f"bearer {token.access_token}"}

    # For all metadata fields, the authorization server MAY replace any
    # invalid values with suitable default values, and it MUST return any
    # such fields to the client in the response.
    # If the client attempts to set an invalid metadata field and the
    # authorization server does not set a default value, the authorization
    # server responds with an error as described in [RFC7591].

    body = {
        "client_id": client.client_id,
        "client_name": "NewAuthlib",
        "token_endpoint_auth_method": "invalid_auth_method",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_client_metadata"


def test_update_scopes_supported(test_client, metadata, token):
    metadata["scopes_supported"] = ["profile", "email"]

    headers = {"Authorization": f"bearer {token.access_token}"}
    body = {
        "client_id": "client-id",
        "scope": "profile email",
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"
    assert resp["client_name"] == "Authlib"
    assert resp["scope"] == "profile email"

    headers = {"Authorization": f"bearer {token.access_token}"}
    body = {
        "client_id": "client-id",
        "scope": "",
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"
    assert resp["client_name"] == "Authlib"

    body = {
        "client_id": "client-id",
        "scope": "profile email address",
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_update_response_types_supported(test_client, metadata, token):
    metadata["response_types_supported"] = ["code"]

    headers = {"Authorization": f"bearer {token.access_token}"}
    body = {
        "client_id": "client-id",
        "response_types": ["code"],
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"
    assert resp["client_name"] == "Authlib"
    assert resp["response_types"] == ["code"]

    # https://datatracker.ietf.org/doc/html/rfc7592#section-2.2
    # If omitted, the default is that the client will use only the "code"
    # response type.
    body = {"client_id": "client-id", "client_name": "Authlib"}
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert "response_types" not in resp

    body = {
        "client_id": "client-id",
        "response_types": ["code", "token"],
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_update_grant_types_supported(test_client, metadata, token):
    metadata["grant_types_supported"] = ["authorization_code", "password"]

    headers = {"Authorization": f"bearer {token.access_token}"}
    body = {
        "client_id": "client-id",
        "grant_types": ["password"],
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"
    assert resp["client_name"] == "Authlib"
    assert resp["grant_types"] == ["password"]

    # https://datatracker.ietf.org/doc/html/rfc7592#section-2.2
    # If omitted, the default behavior is that the client will use only
    # the "authorization_code" Grant Type.
    body = {"client_id": "client-id", "client_name": "Authlib"}
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert "client_id" in resp
    assert resp["client_name"] == "Authlib"
    assert "grant_types" not in resp

    body = {
        "client_id": "client-id",
        "grant_types": ["client_credentials"],
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_update_token_endpoint_auth_methods_supported(test_client, metadata, token):
    metadata["token_endpoint_auth_methods_supported"] = ["client_secret_basic"]

    headers = {"Authorization": f"bearer {token.access_token}"}
    body = {
        "client_id": "client-id",
        "token_endpoint_auth_method": "client_secret_basic",
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_id"] == "client-id"
    assert resp["client_name"] == "Authlib"
    assert resp["token_endpoint_auth_method"] == "client_secret_basic"

    body = {
        "client_id": "client-id",
        "token_endpoint_auth_method": "none",
        "client_name": "Authlib",
    }
    rv = test_client.put("/configure_client/client-id", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] in "invalid_client_metadata"


def test_delete_client(test_client, client, token):
    assert client.client_name == "Authlib"
    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.delete("/configure_client/client-id", headers=headers)
    assert rv.status_code == 204
    assert not rv.data


def test_delete_access_denied(test_client):
    rv = test_client.delete("/configure_client/client-id")
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"

    headers = {"Authorization": "bearer invalid_token"}
    rv = test_client.delete("/configure_client/client-id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"

    headers = {"Authorization": "bearer unauthorized_token"}
    rv = test_client.delete(
        "/configure_client/client-id",
        json={"client_id": "client-id", "client_name": "new client_name"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "access_denied"


def test_delete_invalid_client(test_client, token):
    # If the client does not exist on this server, the server MUST respond
    # with HTTP 401 Unauthorized, and the registration access token used to
    # make this request SHOULD be immediately revoked.

    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.delete("/configure_client/invalid_client_id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 401
    assert resp["error"] == "invalid_client"


def test_delete_unauthorized_client(test_client, token):
    # If the client does not have permission to read its record, the server
    # MUST return an HTTP 403 Forbidden.

    client = Client(
        client_id="unauthorized_client_id",
        client_secret="unauthorized_client_secret",
    )
    db.session.add(client)

    headers = {"Authorization": f"bearer {token.access_token}"}
    rv = test_client.delete("/configure_client/unauthorized_client_id", headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 403
    assert resp["error"] == "unauthorized_client"
