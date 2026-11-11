import time

import pytest
from flask import json
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwk import RSAKey

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint as _ClientRegistrationEndpoint,
)
from tests.util import INVALID_JSON_BODIES
from tests.util import read_file_path

from .models import Client
from .models import db


class ClientRegistrationEndpoint(_ClientRegistrationEndpoint):
    software_statement_alg_values_supported = ["RS256"]

    def authenticate_token(self, request):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header != "bearer invalid_token":
            request.user_id = 1
            return auth_header

    def resolve_public_key(self, request):
        return RSAKey.import_key(read_file_path("rsa_public.pem"))

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


def test_missing_token(test_client):
    """A request without token gets a 401 response with no error code."""
    rv = test_client.post("/create_client", json={})
    resp = json.loads(rv.data)
    assert rv.status_code == 401
    assert "error" not in resp
    assert rv.headers["WWW-Authenticate"] == "Bearer"


def test_invalid_token(test_client):
    """An invalid initial access token gets a 401 invalid_token error."""
    headers = {"Authorization": "bearer invalid_token"}
    rv = test_client.post("/create_client", json={}, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 401
    assert resp["error"] == "invalid_token"
    assert rv.headers["WWW-Authenticate"].startswith('Bearer error="invalid_token"')


def test_open_registration(test_client, app, server, metadata):
    """Open registration accepts requests without token."""

    class OpenClientRegistration(ClientRegistrationEndpoint):
        ENDPOINT_NAME = "open_client_registration"

        def authenticate_token(self, request):
            request.user_id = 1
            return True

        def get_server_metadata(self):
            return metadata

    server.register_endpoint(OpenClientRegistration)

    @app.route("/open_create_client", methods=["POST"])
    def open_create_client():
        return server.create_endpoint_response("open_client_registration")

    rv = test_client.post("/open_create_client", json={"client_name": "Authlib"})
    resp = json.loads(rv.data)
    assert rv.status_code == 201
    assert resp["client_name"] == "Authlib"


def test_invalid_request(test_client):
    headers = {"Authorization": "bearer abc"}
    rv = test_client.post("/create_client", json={}, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


@pytest.mark.parametrize("body", INVALID_JSON_BODIES)
def test_body_not_json_object(test_client, body):
    """A body that is not a JSON object gets an invalid_request error."""
    headers = {"Authorization": "bearer abc"}
    rv = test_client.post(
        "/create_client", data=body, content_type="application/json", headers=headers
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_body_without_json_content_type(test_client):
    """The body is read as JSON whatever the Content-Type."""
    headers = {"Authorization": "bearer abc"}
    rv = test_client.post(
        "/create_client",
        data='{"client_name": "Authlib"}',
        content_type="text/plain",
        headers=headers,
    )
    assert rv.status_code == 201
    assert json.loads(rv.data)["client_name"] == "Authlib"


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


@pytest.mark.filterwarnings(
    "ignore:Using implicit key type is not recommended:joserfc.errors.SecurityWarning"
)
def test_software_statement_raw_public_key(test_client, server):
    """A raw PEM public key is still accepted but deprecated."""

    class RawKeyClientRegistrationEndpoint(ClientRegistrationEndpoint):
        def get_server_metadata(self):
            return {}

        def resolve_public_key(self, request):
            return read_file_path("rsa_public.pem")

    server._endpoints[ClientRegistrationEndpoint.ENDPOINT_NAME] = [
        RawKeyClientRegistrationEndpoint(server)
    ]
    payload = {"software_id": "uuid-123", "client_name": "Authlib"}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    body = {"software_statement": jwt.encode({"alg": "RS256"}, payload, key)}
    headers = {"Authorization": "bearer abc"}
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
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

    keyset = KeySet.generate_key_set("EC", "P-256", count=1)
    valid_jwks = keyset.as_dict(private=False)

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


@pytest.mark.parametrize(
    "jwks",
    [
        KeySet.generate_key_set("oct", 256, count=1).as_dict(private=True),
        KeySet.generate_key_set("EC", "P-256", count=1).as_dict(private=True),
        {
            "keys": [
                *KeySet.generate_key_set("EC", "P-256", count=1).as_dict(private=False)[
                    "keys"
                ],
                *KeySet.generate_key_set("oct", 256, count=1).as_dict()["keys"],
            ]
        },
    ],
)
def test_jwks_rejects_private_keys(test_client, jwks):
    """jwks only accepts public keys."""
    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib", "jwks": jwks}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata"
    assert "jwks" in resp["error_description"]


@pytest.mark.parametrize(
    "client_metadata",
    [
        {"scope": 5},
        {"scope": ["profile"]},
        {"grant_types": 5},
        {"grant_types": "authorization_code"},
        {"response_types": [5]},
        {"redirect_uris": [5]},
        {"token_endpoint_auth_method": ["none"]},
        {"client_name": {"en": "Client"}},
        {"jwks": []},
        {"jwks": {}},
        {"jwks": {"keys": 5}},
    ],
)
@pytest.mark.parametrize("with_metadata", [True, False])
def test_invalid_metadata_type(test_client, metadata, client_metadata, with_metadata):
    """Client metadata with an unexpected type is refused."""
    if with_metadata:
        metadata.update(
            {
                "scopes_supported": ["profile"],
                "grant_types_supported": ["authorization_code"],
                "response_types_supported": ["code"],
                "token_endpoint_auth_methods_supported": ["none"],
            }
        )

    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib", **client_metadata}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_client_metadata"


def test_null_metadata_uses_default(test_client):
    """A null client metadata is ignored, so its default value applies."""
    headers = {"Authorization": "bearer abc"}
    body = {"client_name": "Authlib", "token_endpoint_auth_method": None}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 201
    assert resp["token_endpoint_auth_method"] == "client_secret_basic"


@pytest.mark.parametrize(
    "time_claims",
    [{"exp": 1000000000}, {"nbf": 9999999999}],
    ids=["expired", "not-yet-valid"],
)
def test_software_statement_time_claims(test_client, time_claims):
    """An expired or not yet valid software statement is refused."""
    payload = {"software_id": "uuid-123", "client_name": "Authlib", **time_claims}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    software_statement = jwt.encode({"alg": "RS256"}, payload, key)

    headers = {"Authorization": "bearer abc"}
    body = {"software_statement": software_statement}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert rv.status_code == 400
    assert resp["error"] == "invalid_software_statement"


def test_software_statement_clock_skew(test_client):
    """A software statement issued a few seconds in the future is accepted."""
    now = int(time.time())
    payload = {"software_id": "uuid-123", "client_name": "Authlib", "iat": now + 5}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    software_statement = jwt.encode({"alg": "RS256"}, payload, key)

    headers = {"Authorization": "bearer abc"}
    body = {"software_statement": software_statement}
    rv = test_client.post("/create_client", json=body, headers=headers)
    assert rv.status_code == 201


@pytest.mark.parametrize(
    "aud",
    ["https://provider.test", ["https://other.test", "https://provider.test"]],
)
def test_software_statement_audience(test_client, metadata, aud):
    """A software statement whose aud contains the issuer is accepted."""
    metadata["issuer"] = "https://provider.test"
    payload = {"software_id": "uuid-123", "client_name": "Authlib", "aud": aud}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    body = {"software_statement": jwt.encode({"alg": "RS256"}, payload, key)}
    headers = {"Authorization": "bearer abc"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_name"] == "Authlib"


@pytest.mark.parametrize(
    "issuer,aud",
    [
        ("https://provider.test", "https://other.test"),
        ("https://provider.test", []),
        ("https://provider.test", 1),
        (None, "https://provider.test"),
    ],
)
def test_software_statement_unexpected_audience(test_client, metadata, issuer, aud):
    """A software statement whose aud does not contain the issuer is rejected."""
    if issuer:
        metadata["issuer"] = issuer

    payload = {"software_id": "uuid-123", "client_name": "Authlib", "aud": aud}
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    body = {"software_statement": jwt.encode({"alg": "RS256"}, payload, key)}
    headers = {"Authorization": "bearer abc"}
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_software_statement"


def test_software_statement_custom_audiences(test_client, server, metadata):
    """get_audiences can accept other aud values than the issuer."""

    class CustomAudiencesEndpoint(ClientRegistrationEndpoint):
        def get_server_metadata(self):
            return metadata

        def get_audiences(self):
            return ["https://provider.test/register"]

    server._endpoints[ClientRegistrationEndpoint.ENDPOINT_NAME] = [
        CustomAudiencesEndpoint(server)
    ]
    metadata["issuer"] = "https://provider.test"
    key = RSAKey.import_key(read_file_path("rsa_private.pem"))
    headers = {"Authorization": "bearer abc"}

    payload = {"client_name": "Authlib", "aud": "https://provider.test/register"}
    body = {"software_statement": jwt.encode({"alg": "RS256"}, payload, key)}
    rv = test_client.post("/create_client", json=body, headers=headers)
    assert json.loads(rv.data)["client_name"] == "Authlib"

    payload = {"client_name": "Authlib", "aud": "https://provider.test"}
    body = {"software_statement": jwt.encode({"alg": "RS256"}, payload, key)}
    rv = test_client.post("/create_client", json=body, headers=headers)
    assert json.loads(rv.data)["error"] == "invalid_software_statement"
