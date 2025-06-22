from flask import json

from authlib.jose import jwt
from authlib.oauth2.rfc7591 import ClientMetadataClaims as OAuth2ClientMetadataClaims
from authlib.oauth2.rfc7591 import (
    ClientRegistrationEndpoint as _ClientRegistrationEndpoint,
)
from authlib.oidc.registration import ClientMetadataClaims as OIDCClientMetadataClaims
from tests.util import read_file_path

from .models import Client
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


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


class OAuthClientRegistrationTest(TestCase):
    def prepare_data(self, endpoint_cls=None, metadata=None):
        app = self.app
        server = create_authorization_server(app)

        if endpoint_cls:
            server.register_endpoint(endpoint_cls)
        else:

            class MyClientRegistration(ClientRegistrationEndpoint):
                def get_server_metadata(self):
                    return metadata

            server.register_endpoint(MyClientRegistration)

        @app.route("/create_client", methods=["POST"])
        def create_client():
            return server.create_endpoint_response("client_registration")

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

    def test_access_denied(self):
        self.prepare_data()
        rv = self.client.post("/create_client", json={})
        resp = json.loads(rv.data)
        assert resp["error"] == "access_denied"

    def test_invalid_request(self):
        self.prepare_data()
        headers = {"Authorization": "bearer abc"}
        rv = self.client.post("/create_client", json={}, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_create_client(self):
        self.prepare_data()
        headers = {"Authorization": "bearer abc"}
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

    def test_software_statement(self):
        payload = {"software_id": "uuid-123", "client_name": "Authlib"}
        s = jwt.encode({"alg": "RS256"}, payload, read_file_path("rsa_private.pem"))
        body = {
            "software_statement": s.decode("utf-8"),
        }

        self.prepare_data()
        headers = {"Authorization": "bearer abc"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

    def test_no_public_key(self):
        class ClientRegistrationEndpoint2(ClientRegistrationEndpoint):
            def get_server_metadata(self):
                return None

            def resolve_public_key(self, request):
                return None

        payload = {"software_id": "uuid-123", "client_name": "Authlib"}
        s = jwt.encode({"alg": "RS256"}, payload, read_file_path("rsa_private.pem"))
        body = {
            "software_statement": s.decode("utf-8"),
        }

        self.prepare_data(ClientRegistrationEndpoint2)
        headers = {"Authorization": "bearer abc"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "unapproved_software_statement"

    def test_scopes_supported(self):
        metadata = {"scopes_supported": ["profile", "email"]}
        self.prepare_data(metadata=metadata)

        headers = {"Authorization": "bearer abc"}
        body = {"scope": "profile email", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        body = {"scope": "profile email address", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_response_types_supported(self):
        metadata = {"response_types_supported": ["code", "code id_token"]}
        self.prepare_data(metadata=metadata)

        headers = {"Authorization": "bearer abc"}
        body = {"response_types": ["code"], "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        # The items order should not matter
        # Extension response types MAY contain a space-delimited (%x20) list of
        # values, where the order of values does not matter (e.g., response
        # type "a b" is the same as "b a").
        headers = {"Authorization": "bearer abc"}
        body = {"response_types": ["id_token code"], "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        self.assertIn("client_id", resp)
        self.assertEqual(resp["client_name"], "Authlib")

        # https://www.rfc-editor.org/rfc/rfc7591.html#section-2
        # If omitted, the default is that the client will use only the "code"
        # response type.
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        body = {"response_types": ["code", "token"], "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_grant_types_supported(self):
        metadata = {"grant_types_supported": ["authorization_code", "password"]}
        self.prepare_data(metadata=metadata)

        headers = {"Authorization": "bearer abc"}
        body = {"grant_types": ["password"], "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        # https://www.rfc-editor.org/rfc/rfc7591.html#section-2
        # If omitted, the default behavior is that the client will use only
        # the "authorization_code" Grant Type.
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        body = {"grant_types": ["client_credentials"], "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_token_endpoint_auth_methods_supported(self):
        metadata = {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        self.prepare_data(metadata=metadata)

        headers = {"Authorization": "bearer abc"}
        body = {
            "token_endpoint_auth_method": "client_secret_basic",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        body = {"token_endpoint_auth_method": "none", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"


class OIDCClientRegistrationTest(TestCase):
    def prepare_data(self, metadata=None):
        self.headers = {"Authorization": "bearer abc"}
        app = self.app
        server = create_authorization_server(app)

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

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

    def test_application_type(self):
        self.prepare_data()

        # Nominal case
        body = {
            "application_type": "web",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["application_type"] == "web"

        # Default case
        # The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
        body = {
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["application_type"] == "web"

        # Error case
        body = {
            "application_type": "invalid",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_token_endpoint_auth_signing_alg_supported(self):
        metadata = {
            "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"]
        }
        self.prepare_data(metadata)

        # Nominal case
        body = {
            "token_endpoint_auth_signing_alg": "ES256",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["token_endpoint_auth_signing_alg"] == "ES256"

        # Default case
        # The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
        body = {
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"

        # Error case
        body = {
            "token_endpoint_auth_signing_alg": "RS512",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_subject_types_supported(self):
        metadata = {"subject_types_supported": ["public", "pairwise"]}
        self.prepare_data(metadata)

        # Nominal case
        body = {"subject_type": "public", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["subject_type"] == "public"

        # Error case
        body = {"subject_type": "invalid", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_id_token_signing_alg_values_supported(self):
        metadata = {"id_token_signing_alg_values_supported": ["RS256", "ES256"]}
        self.prepare_data(metadata)

        # Default
        # The default, if omitted, is RS256.
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["id_token_signed_response_alg"] == "RS256"

        # Nominal case
        body = {"id_token_signed_response_alg": "ES256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["id_token_signed_response_alg"] == "ES256"

        # Error case
        body = {"id_token_signed_response_alg": "RS512", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_id_token_signing_alg_values_none(self):
        # The value none MUST NOT be used as the ID Token alg value unless the Client uses
        # only Response Types that return no ID Token from the Authorization Endpoint
        # (such as when only using the Authorization Code Flow).
        metadata = {"id_token_signing_alg_values_supported": ["none", "RS256", "ES256"]}
        self.prepare_data(metadata)

        # Nominal case
        body = {
            "id_token_signed_response_alg": "none",
            "client_name": "Authlib",
            "response_type": "code",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        self.assertIn("client_id", resp)
        self.assertEqual(resp["client_name"], "Authlib")
        self.assertEqual(resp["id_token_signed_response_alg"], "none")

        # Error case
        body = {
            "id_token_signed_response_alg": "none",
            "client_name": "Authlib",
            "response_type": "id_token",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        self.assertIn(resp["error"], "invalid_client_metadata")

    def test_id_token_encryption_alg_values_supported(self):
        metadata = {"id_token_encryption_alg_values_supported": ["RS256", "ES256"]}
        self.prepare_data(metadata)

        # Default case
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert "id_token_encrypted_response_enc" not in resp

        # If id_token_encrypted_response_alg is specified, the default
        # id_token_encrypted_response_enc value is A128CBC-HS256.
        body = {"id_token_encrypted_response_alg": "RS256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["id_token_encrypted_response_enc"] == "A128CBC-HS256"

        # Nominal case
        body = {"id_token_encrypted_response_alg": "ES256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["id_token_encrypted_response_alg"] == "ES256"

        # Error case
        body = {"id_token_encrypted_response_alg": "RS512", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_id_token_encryption_enc_values_supported(self):
        metadata = {
            "id_token_encryption_enc_values_supported": ["A128CBC-HS256", "A256GCM"]
        }
        self.prepare_data(metadata)

        # Nominal case
        body = {
            "id_token_encrypted_response_alg": "RS256",
            "id_token_encrypted_response_enc": "A256GCM",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["id_token_encrypted_response_alg"] == "RS256"
        assert resp["id_token_encrypted_response_enc"] == "A256GCM"

        # Error case: missing id_token_encrypted_response_alg
        body = {"id_token_encrypted_response_enc": "A256GCM", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

        # Error case: alg not in server metadata
        body = {"id_token_encrypted_response_enc": "A128GCM", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_userinfo_signing_alg_values_supported(self):
        metadata = {"userinfo_signing_alg_values_supported": ["RS256", "ES256"]}
        self.prepare_data(metadata)

        # Nominal case
        body = {"userinfo_signed_response_alg": "ES256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["userinfo_signed_response_alg"] == "ES256"

        # Error case
        body = {"userinfo_signed_response_alg": "RS512", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_userinfo_encryption_alg_values_supported(self):
        metadata = {"userinfo_encryption_alg_values_supported": ["RS256", "ES256"]}
        self.prepare_data(metadata)

        # Nominal case
        body = {"userinfo_encrypted_response_alg": "ES256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["userinfo_encrypted_response_alg"] == "ES256"

        # Error case
        body = {"userinfo_encrypted_response_alg": "RS512", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_userinfo_encryption_enc_values_supported(self):
        metadata = {
            "userinfo_encryption_enc_values_supported": ["A128CBC-HS256", "A256GCM"]
        }
        self.prepare_data(metadata)

        # Default case
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert "userinfo_encrypted_response_enc" not in resp

        # If userinfo_encrypted_response_alg is specified, the default
        # userinfo_encrypted_response_enc value is A128CBC-HS256.
        body = {"userinfo_encrypted_response_alg": "RS256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
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
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["userinfo_encrypted_response_alg"] == "RS256"
        assert resp["userinfo_encrypted_response_enc"] == "A256GCM"

        # Error case: no userinfo_encrypted_response_alg
        body = {"userinfo_encrypted_response_enc": "A256GCM", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

        # Error case: alg not in server metadata
        body = {"userinfo_encrypted_response_enc": "A128GCM", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_acr_values_supported(self):
        metadata = {
            "acr_values_supported": [
                "urn:mace:incommon:iap:silver",
                "urn:mace:incommon:iap:bronze",
            ],
        }
        self.prepare_data(metadata)

        # Nominal case
        body = {
            "default_acr_values": ["urn:mace:incommon:iap:silver"],
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
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
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_request_object_signing_alg_values_supported(self):
        metadata = {"request_object_signing_alg_values_supported": ["RS256", "ES256"]}
        self.prepare_data(metadata)

        # Nominal case
        body = {"request_object_signing_alg": "ES256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["request_object_signing_alg"] == "ES256"

        # Error case
        body = {"request_object_signing_alg": "RS512", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_request_object_encryption_alg_values_supported(self):
        metadata = {
            "request_object_encryption_alg_values_supported": ["RS256", "ES256"]
        }
        self.prepare_data(metadata)

        # Nominal case
        body = {
            "request_object_encryption_alg": "ES256",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["request_object_encryption_alg"] == "ES256"

        # Error case
        body = {
            "request_object_encryption_alg": "RS512",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_request_object_encryption_enc_values_supported(self):
        metadata = {
            "request_object_encryption_enc_values_supported": [
                "A128CBC-HS256",
                "A256GCM",
            ]
        }
        self.prepare_data(metadata)

        # Default case
        body = {"client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert "request_object_encryption_enc" not in resp

        # If request_object_encryption_alg is specified, the default
        # request_object_encryption_enc value is A128CBC-HS256.
        body = {"request_object_encryption_alg": "RS256", "client_name": "Authlib"}
        rv = self.client.post("/create_client", json=body, headers=self.headers)
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
        rv = self.client.post("/create_client", json=body, headers=self.headers)
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
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

        # Error case: alg not in server metadata
        body = {
            "request_object_encryption_enc": "A128GCM",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_require_auth_time(self):
        self.prepare_data()

        # Default case
        body = {
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["require_auth_time"] is False

        # Nominal case
        body = {
            "require_auth_time": True,
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["require_auth_time"] is True

        # Error case
        body = {
            "require_auth_time": "invalid",
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"

    def test_redirect_uri(self):
        """RFC6749 indicate that fragments are forbidden in redirect_uri.

            The redirection endpoint URI MUST be an absolute URI as defined by
            [RFC3986] Section 4.3.  [...]  The endpoint URI MUST NOT include a
            fragment component.

        https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2
        """
        self.prepare_data()

        # Nominal case
        body = {
            "redirect_uris": ["https://client.test"],
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert "client_id" in resp
        assert resp["client_name"] == "Authlib"
        assert resp["redirect_uris"] == ["https://client.test"]

        # Error case
        body = {
            "redirect_uris": ["https://client.test#fragment"],
            "client_name": "Authlib",
        }
        rv = self.client.post("/create_client", json=body, headers=self.headers)
        resp = json.loads(rv.data)
        assert resp["error"] in "invalid_client_metadata"
