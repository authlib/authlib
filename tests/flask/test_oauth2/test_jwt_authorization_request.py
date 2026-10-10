import json
from unittest.mock import Mock

import pytest
from joserfc import jwk
from joserfc import jwt

from authlib.common.urls import add_params_to_uri
from authlib.oauth2 import rfc7591
from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import save_authorization_code

authorize_url = "/oauth/authorize"


@pytest.fixture
def metadata():
    return {}


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def client_registration_endpoint(app, server, metadata, db):
    class ClientRegistrationEndpoint(rfc7591.ClientRegistrationEndpoint):
        software_statement_alg_values_supported = ["RS256"]

        def authenticate_token(self, request):
            auth_header = request.headers.get("Authorization")
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

        def get_server_metadata(self):
            return metadata

    server.register_endpoint(
        ClientRegistrationEndpoint(
            claims_classes=[
                rfc7591.ClientMetadataClaims,
                rfc9101.ClientMetadataClaims,
            ]
        )
    )

    @app.route("/create_client", methods=["POST"])
    def create_client():
        return server.create_endpoint_response(ClientRegistrationEndpoint.ENDPOINT_NAME)


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "jwks": read_file_path("jwks_public.json"),
            "require_signed_request_object": False,
            "request_uris": ["https://client.test/request_object"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def register_request_object_extension(
    server,
    metadata=None,
    request_object=None,
    support_request=True,
    support_request_uri=True,
):
    class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

        def get_request_object(self, request_uri: str):
            return request_object

        def get_server_metadata(self):
            return metadata or {}

        def get_client_require_signed_request_object(self, client):
            return client.client_metadata.get("require_signed_request_object", False)

        def get_client_request_uris(self, client):
            return client.client_metadata.get("request_uris", [])

    extension = JWTAuthenticationRequest(
        support_request=support_request, support_request_uri=support_request_uri
    )
    server.register_extension(extension)
    return extension


def test_request_parameter_get(test_client, server):
    """Pass the authentication payload in a JWT in the request query parameter."""
    register_request_object_extension(server)
    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )
    rv = test_client.get(url)
    assert rv.data == b"ok"


def test_request_uri_parameter_get(test_client, server):
    """Pass the authentication payload in a JWT in the request_uri query parameter."""
    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    register_request_object_extension(server, request_object=request_obj)

    url = add_params_to_uri(
        authorize_url,
        {
            "client_id": "client-id",
            "request_uri": "https://client.test/request_object",
        },
    )
    rv = test_client.get(url)
    assert rv.data == b"ok"


def test_request_and_request_uri_parameters(test_client, server):
    """Passing both requests and request_uri parameters should return an error."""

    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    register_request_object_extension(server, request_object=request_obj)

    url = add_params_to_uri(
        authorize_url,
        {
            "client_id": "client-id",
            "request": request_obj,
            "request_uri": "https://client.test/request_object",
        },
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "The 'request' and 'request_uri' parameters are mutually exclusive."
    )


def test_neither_request_nor_request_uri_parameter(test_client, server):
    """Passing parameters in the query string and not in a request object should still work."""

    register_request_object_extension(server)
    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": "client-id"}
    )
    rv = test_client.get(url)
    assert rv.data == b"ok"


def test_server_require_request_object(test_client, server, metadata):
    """When server metadata 'require_signed_request_object' is true, request objects must be used."""
    metadata["require_signed_request_object"] = True
    register_request_object_extension(server, metadata=metadata)
    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": "client-id"}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "Authorization requests for this server must use signed request objects."
    )


def test_server_require_request_object_alg_none(test_client, server, metadata):
    """When server metadata 'require_signed_request_object' is true, the JWT alg cannot be none."""

    metadata["require_signed_request_object"] = True
    register_request_object_extension(server, metadata=metadata)
    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "none"},
        payload,
        jwk.import_key(read_file_path("jwk_private.json")),
        algorithms=["none"],
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "Authorization requests must be signed with supported algorithms."
    )


def test_client_require_signed_request_object(test_client, client, server, db):
    """When client metadata 'require_signed_request_object' is true, request objects must be used."""

    register_request_object_extension(server)
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "jwks": read_file_path("jwks_public.json"),
            "require_signed_request_object": True,
        }
    )
    db.session.add(client)
    db.session.commit()

    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": "client-id"}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "Authorization requests for this client must use signed request objects."
    )


def test_client_require_signed_request_object_alg_none(test_client, client, server, db):
    """When client metadata 'require_signed_request_object' is true, the JWT alg cannot be none."""

    register_request_object_extension(server)
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "jwks": read_file_path("jwks_public.json"),
            "require_signed_request_object": True,
        }
    )
    db.session.add(client)
    db.session.commit()

    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "none"}, payload, jwk.generate_key("oct"), algorithms=["none"]
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "Authorization requests must be signed with supported algorithms."
    )


def test_unsupported_request_parameter(test_client, server):
    """Passing the request parameter when unsupported should raise a 'request_not_supported' error."""

    register_request_object_extension(server, support_request=False)
    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "request_not_supported"
    assert (
        params["error_description"]
        == "The authorization server does not support the use of the request parameter."
    )


def test_unsupported_request_uri_parameter(test_client, server):
    """Passing the request parameter when unsupported should raise a 'request_uri_not_supported' error."""

    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    register_request_object_extension(
        server, request_object=request_obj, support_request_uri=False
    )

    url = add_params_to_uri(
        authorize_url,
        {
            "client_id": "client-id",
            "request_uri": "https://client.test/request_object",
        },
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "request_uri_not_supported"
    assert (
        params["error_description"]
        == "The authorization server does not support the use of the request_uri parameter."
    )


def test_invalid_request_uri_parameter(test_client, server):
    """Invalid request_uri (or unreachable etc.) should raise a invalid_request_uri error."""

    register_request_object_extension(server)
    url = add_params_to_uri(
        authorize_url,
        {
            "client_id": "client-id",
            "request_uri": "https://client.test/request_object",
        },
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request_uri"
    assert (
        params["error_description"]
        == "The request_uri in the authorization request returns an error or contains invalid data."
    )


def test_invalid_request_object(test_client, server):
    """Invalid request object should raise a invalid_request_object error."""

    register_request_object_extension(server)
    url = add_params_to_uri(
        authorize_url,
        {
            "client_id": "client-id",
            "request": "invalid",
        },
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request_object"
    assert (
        params["error_description"]
        == "The request parameter contains an invalid Request Object."
    )


def test_missing_client_id(test_client, server):
    """The client_id parameter is mandatory."""

    register_request_object_extension(server)
    payload = {"response_type": "code", "client_id": "client-id"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    url = add_params_to_uri(authorize_url, {"request": request_obj})

    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_client"
    assert params["error_description"] == "Missing 'client_id' parameter."


def test_invalid_client_id(test_client, server):
    """The client_id parameter is mandatory."""

    register_request_object_extension(server)
    payload = {"response_type": "code", "client_id": "invalid"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "invalid", "request": request_obj}
    )

    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_client"
    assert params["error_description"] == "The client does not exist on this server."


def test_different_client_id(test_client, server):
    """The client_id parameter should be the same in the request payload and the request object."""

    register_request_object_extension(server)
    payload = {"response_type": "code", "client_id": "other-code-client"}
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "The 'client_id' claim from the request parameters and the request object claims don't match."
    )


def test_request_param_in_request_object(test_client, server):
    """The request and request_uri parameters should not be present in the request object."""

    register_request_object_extension(server)
    payload = {
        "response_type": "code",
        "client_id": "client-id",
        "request_uri": "https://client.test/request_object",
    }
    request_obj = jwt.encode(
        {"alg": "RS256"}, payload, jwk.import_key(read_file_path("jwk_private.json"))
    )
    url = add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )
    rv = test_client.get(url)
    params = json.loads(rv.data)
    assert params["error"] == "invalid_request"
    assert (
        params["error_description"]
        == "The 'request' and 'request_uri' parameters must not be included in the request object."
    )


def test_registration(test_client, server):
    """The 'require_signed_request_object' parameter should be available for client registration."""
    register_request_object_extension(server)
    headers = {"Authorization": "bearer abc"}

    # Default case
    body = {
        "client_name": "Authlib",
    }
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_name"] == "Authlib"
    assert resp["require_signed_request_object"] is False

    # Nominal case
    body = {
        "require_signed_request_object": True,
        "client_name": "Authlib",
    }
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["client_name"] == "Authlib"
    assert resp["require_signed_request_object"] is True

    # Error case
    body = {
        "require_signed_request_object": "invalid",
        "client_name": "Authlib",
    }
    rv = test_client.post("/create_client", json=body, headers=headers)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata"


@pytest.mark.parametrize("require_signed", ["server", "client", None])
@pytest.mark.parametrize("algorithm_source", ["metadata", "override", "only_none"])
@pytest.mark.parametrize("parameter", ["request", "request_uri"])
@pytest.mark.parametrize("algorithm", ["none", "RS256"])
def test_signature_requirement_with_explicit_algorithms(
    test_client,
    server,
    client,
    db,
    require_signed,
    algorithm_source,
    parameter,
    algorithm,
):
    metadata = {"require_signed_request_object": require_signed == "server"}
    if require_signed == "client":
        client.set_client_metadata(
            {**client.client_metadata, "require_signed_request_object": True}
        )
        db.session.commit()
    request_object = jwt.encode(
        {"alg": algorithm},
        {"client_id": "client-id", "response_type": "code"},
        jwk.import_key(read_file_path("jwk_private.json")),
        algorithms=[algorithm],
    )
    if algorithm_source == "metadata":
        metadata["request_object_signing_alg_values_supported"] = ["RS256", "none"]
    elif algorithm_source == "only_none":
        metadata["request_object_signing_alg_values_supported"] = ["none"]
    extension = register_request_object_extension(
        server, metadata=metadata, request_object=request_object
    )
    if algorithm_source == "override":
        extension.get_request_object_signing_algorithms = lambda client: [
            "RS256",
            "none",
        ]
    value = (
        request_object
        if parameter == "request"
        else "https://client.test/request_object"
    )
    response = test_client.get(
        add_params_to_uri(authorize_url, {"client_id": "client-id", parameter: value})
    )
    if (require_signed and algorithm == "none") or (
        algorithm_source == "only_none" and algorithm == "RS256"
    ):
        assert response.status_code == 400
        assert response.json["error"] == "invalid_request"
        assert response.json["error_description"] == (
            "Authorization requests must be signed with supported algorithms."
        )
    else:
        assert response.data == b"ok"


@pytest.mark.parametrize("require_registration", [False, True])
@pytest.mark.parametrize(
    "request_uri",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/admin",
        "file:///etc/passwd",
        "https://other.test/request_object",
        "https://client.test/request_object/extra",
        "https://client.test/request_object?target=internal",
        "https://client.test@other.test/request_object",
        "",
    ],
)
def test_unregistered_request_uri_rejected_before_fetch(
    test_client, server, require_registration, request_uri
):
    extension = register_request_object_extension(
        server, metadata={"require_request_uri_registration": require_registration}
    )
    extension.get_request_object = Mock(return_value="unexpected fetch")
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "client-id", "request_uri": request_uri, "state": "s"},
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_uri"
    assert response.json["state"] == "s"
    extension.get_request_object.assert_not_called()


@pytest.mark.parametrize("require_registration", [False, True])
@pytest.mark.parametrize("registered", [False, True])
def test_custom_request_uri_validator_and_registration(
    test_client, server, client, db, require_registration, registered
):
    request_uri = "urn:example:stored-request"
    if registered:
        client.set_client_metadata(
            {**client.client_metadata, "request_uris": [request_uri]}
        )
        db.session.commit()
    request_object = jwt.encode(
        {"alg": "RS256"},
        {"client_id": "client-id", "response_type": "code"},
        jwk.import_key(read_file_path("jwk_private.json")),
    )
    extension = register_request_object_extension(
        server, metadata={"require_request_uri_registration": require_registration}
    )
    extension.validate_request_uri = lambda uri, client: uri == request_uri
    extension.get_request_object = Mock(return_value=request_object)
    response = test_client.get(
        add_params_to_uri(
            authorize_url, {"client_id": "client-id", "request_uri": request_uri}
        )
    )
    if require_registration and not registered:
        assert response.status_code == 400
        assert response.json["error"] == "invalid_request_uri"
        extension.get_request_object.assert_not_called()
    else:
        assert response.data == b"ok"
        extension.get_request_object.assert_called_once_with(request_uri)


def test_request_uri_without_registered_uris(test_client, server):
    extension = register_request_object_extension(server)
    extension.get_client_request_uris = lambda client: []
    extension.get_request_object = Mock(return_value="unexpected fetch")
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request_uri": "https://client.test/request_object",
            },
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_uri"
    extension.get_request_object.assert_not_called()


@pytest.mark.parametrize("parameter", ["request", "request_uri"])
def test_invalid_request_object_signature(test_client, server, parameter):
    request_object = jwt.encode(
        {"alg": "RS256"},
        {"client_id": "client-id", "response_type": "code"},
        jwk.generate_key("RSA", 2048),
    )
    register_request_object_extension(
        server,
        metadata={"require_signed_request_object": True},
        request_object=request_object,
    )
    value = (
        request_object
        if parameter == "request"
        else "https://client.test/request_object"
    )
    response = test_client.get(
        add_params_to_uri(authorize_url, {"client_id": "client-id", parameter: value})
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_custom_request_uri_validator_rejects_registered_uri(test_client, server):
    extension = register_request_object_extension(server)
    extension.validate_request_uri = lambda uri, client: False
    extension.get_request_object = Mock(return_value="unexpected fetch")
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {
                "client_id": "client-id",
                "request_uri": "https://client.test/request_object",
            },
        )
    )
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_uri"
    extension.get_request_object.assert_not_called()
