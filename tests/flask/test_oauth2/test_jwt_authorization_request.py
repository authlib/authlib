import json

from authlib.common.urls import add_params_to_uri
from authlib.jose import jwt
from authlib.oauth2 import rfc7591
from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class AuthorizationCodeTest(TestCase):
    def register_grant(self, server):
        server.register_grant(AuthorizationCodeGrant)

    def prepare_data(
        self,
        request_object=None,
        support_request=True,
        support_request_uri=True,
        metadata=None,
        client_require_signed_request_object=False,
    ):
        class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
            def resolve_client_public_key(self, client):
                return read_file_path("jwk_public.json")

            def get_request_object(self, request_uri: str):
                return request_object

            def get_server_metadata(self):
                return metadata

            def get_client_require_signed_request_object(self, client):
                return client.client_metadata.get(
                    "require_signed_request_object", False
                )

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

        server = create_authorization_server(self.app)
        server.register_extension(
            JWTAuthenticationRequest(
                support_request=support_request, support_request_uri=support_request_uri
            )
        )
        self.register_grant(server)
        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    rfc9101.ClientMetadataClaims,
                ]
            )
        )
        self.server = server
        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

        @self.app.route("/create_client", methods=["POST"])
        def create_client():
            return server.create_endpoint_response("client_registration")

        client = Client(
            user_id=user.id,
            client_id="code-client",
            client_secret="code-secret",
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["https://a.b"],
                "scope": "profile address",
                "token_endpoint_auth_method": "client_secret_basic",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "jwks": read_file_path("jwks_public.json"),
                "require_signed_request_object": client_require_signed_request_object,
            }
        )
        self.authorize_url = "/oauth/authorize"
        db.session.add(client)
        db.session.commit()

    def test_request_parameter_get(self):
        """Pass the authentication payload in a JWT in the request query parameter."""

        self.prepare_data()
        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "code-client", "request": request_obj}
        )
        rv = self.client.get(url)
        assert rv.data == b"ok"

    def test_request_uri_parameter_get(self):
        """Pass the authentication payload in a JWT in the request_uri query parameter."""

        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        self.prepare_data(request_object=request_obj)

        url = add_params_to_uri(
            self.authorize_url,
            {
                "client_id": "code-client",
                "request_uri": "https://client.test/request_object",
            },
        )
        rv = self.client.get(url)
        assert rv.data == b"ok"

    def test_request_and_request_uri_parameters(self):
        """Passing both requests and request_uri parameters should return an error."""

        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        self.prepare_data(request_object=request_obj)

        url = add_params_to_uri(
            self.authorize_url,
            {
                "client_id": "code-client",
                "request": request_obj,
                "request_uri": "https://client.test/request_object",
            },
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "The 'request' and 'request_uri' parameters are mutually exclusive."
        )

    def test_neither_request_nor_request_uri_parameter(self):
        """Passing parameters in the query string and not in a request object should still work."""

        self.prepare_data()
        url = add_params_to_uri(
            self.authorize_url, {"response_type": "code", "client_id": "code-client"}
        )
        rv = self.client.get(url)
        assert rv.data == b"ok"

    def test_server_require_request_object(self):
        """When server metadata 'require_signed_request_object' is true, request objects must be used."""

        self.prepare_data(metadata={"require_signed_request_object": True})
        url = add_params_to_uri(
            self.authorize_url, {"response_type": "code", "client_id": "code-client"}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "Authorization requests for this server must use signed request objects."
        )

    def test_server_require_request_object_alg_none(self):
        """When server metadata 'require_signed_request_object' is true, the JWT alg cannot be none."""

        self.prepare_data(metadata={"require_signed_request_object": True})
        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "none"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "code-client", "request": request_obj}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "Authorization requests for this server must use signed request objects."
        )

    def test_client_require_signed_request_object(self):
        """When client metadata 'require_signed_request_object' is true, request objects must be used."""

        self.prepare_data(client_require_signed_request_object=True)
        url = add_params_to_uri(
            self.authorize_url, {"response_type": "code", "client_id": "code-client"}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "Authorization requests for this client must use signed request objects."
        )

    def test_client_require_signed_request_object_alg_none(self):
        """When client metadata 'require_signed_request_object' is true, the JWT alg cannot be none."""

        self.prepare_data(client_require_signed_request_object=True)
        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode({"alg": "none"}, payload, "")
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "code-client", "request": request_obj}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "Authorization requests for this client must use signed request objects."
        )

    def test_unsupported_request_parameter(self):
        """Passing the request parameter when unsupported should raise a 'request_not_supported' error."""

        self.prepare_data(support_request=False)
        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "code-client", "request": request_obj}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "request_not_supported"
        assert (
            params["error_description"]
            == "The authorization server does not support the use of the request parameter."
        )

    def test_unsupported_request_uri_parameter(self):
        """Passing the request parameter when unsupported should raise a 'request_uri_not_supported' error."""

        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        self.prepare_data(request_object=request_obj, support_request_uri=False)

        url = add_params_to_uri(
            self.authorize_url,
            {
                "client_id": "code-client",
                "request_uri": "https://client.test/request_object",
            },
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "request_uri_not_supported"
        assert (
            params["error_description"]
            == "The authorization server does not support the use of the request_uri parameter."
        )

    def test_invalid_request_uri_parameter(self):
        """Invalid request_uri (or unreachable etc.) should raise a invalid_request_uri error."""

        self.prepare_data()
        url = add_params_to_uri(
            self.authorize_url,
            {
                "client_id": "code-client",
                "request_uri": "https://client.test/request_object",
            },
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request_uri"
        assert (
            params["error_description"]
            == "The request_uri in the authorization request returns an error or contains invalid data."
        )

    def test_invalid_request_object(self):
        """Invalid request object should raise a invalid_request_object error."""

        self.prepare_data()
        url = add_params_to_uri(
            self.authorize_url,
            {
                "client_id": "code-client",
                "request": "invalid",
            },
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request_object"
        assert (
            params["error_description"]
            == "The request parameter contains an invalid Request Object."
        )

    def test_missing_client_id(self):
        """The client_id parameter is mandatory."""

        self.prepare_data()
        payload = {"response_type": "code", "client_id": "code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(self.authorize_url, {"request": request_obj})

        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_client"
        assert params["error_description"] == "Missing 'client_id' parameter."

    def test_invalid_client_id(self):
        """The client_id parameter is mandatory."""

        self.prepare_data()
        payload = {"response_type": "code", "client_id": "invalid"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "invalid", "request": request_obj}
        )

        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_client"
        assert (
            params["error_description"] == "The client does not exist on this server."
        )

    def test_different_client_id(self):
        """The client_id parameter should be the same in the request payload and the request object."""

        self.prepare_data()
        payload = {"response_type": "code", "client_id": "other-code-client"}
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "code-client", "request": request_obj}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "The 'client_id' claim from the request parameters and the request object claims don't match."
        )

    def test_request_param_in_request_object(self):
        """The request and request_uri parameters should not be present in the request object."""

        self.prepare_data()
        payload = {
            "response_type": "code",
            "client_id": "code-client",
            "request_uri": "https://client.test/request_object",
        }
        request_obj = jwt.encode(
            {"alg": "RS256"}, payload, read_file_path("jwk_private.json")
        )
        url = add_params_to_uri(
            self.authorize_url, {"client_id": "code-client", "request": request_obj}
        )
        rv = self.client.get(url)
        params = json.loads(rv.data)
        assert params["error"] == "invalid_request"
        assert (
            params["error_description"]
            == "The 'request' and 'request_uri' parameters must not be included in the request object."
        )

    def test_registration(self):
        """The 'require_signed_request_object' parameter should be available for client registration."""
        self.prepare_data()
        headers = {"Authorization": "bearer abc"}

        # Default case
        body = {
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_name"] == "Authlib"
        assert resp["require_signed_request_object"] is False

        # Nominal case
        body = {
            "require_signed_request_object": True,
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["client_name"] == "Authlib"
        assert resp["require_signed_request_object"] is True

        # Error case
        body = {
            "require_signed_request_object": "invalid",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client_metadata"
