import json

from authlib.oauth2.rfc6749 import grants

from .models import Client
from .models import User
from .oauth2_server import TestCase


class PasswordTest(TestCase):
    def create_server(self):
        server = super().create_server()
        server.register_grant(grants.ClientCredentialsGrant)
        return server

    def prepare_data(self, grant_type="client_credentials", scope=""):
        user = User(username="foo")
        user.save()
        client = Client(
            user_id=user.pk,
            client_id="client",
            client_secret="secret",
            scope=scope,
            grant_type=grant_type,
            token_endpoint_auth_method="client_secret_basic",
            default_redirect_uri="https://a.b",
        )
        client.save()

    def test_invalid_client(self):
        server = self.create_server()
        self.prepare_data()
        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "client_credentials"},
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "client_credentials"},
            HTTP_AUTHORIZATION=self.create_basic_auth("invalid", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

    def test_invalid_scope(self):
        server = self.create_server()
        server.scopes_supported = ["profile"]
        self.prepare_data()
        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "invalid"},
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 400
        data = json.loads(resp.content)
        assert data["error"] == "invalid_scope"

    def test_invalid_request(self):
        server = self.create_server()
        self.prepare_data()

        request = self.factory.get(
            "/oauth/token?grant_type=client_credentials",
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 400
        data = json.loads(resp.content)
        assert data["error"] == "unsupported_grant_type"

    def test_unauthorized_client(self):
        server = self.create_server()
        self.prepare_data(grant_type="invalid")
        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "client_credentials"},
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 400
        data = json.loads(resp.content)
        assert data["error"] == "unauthorized_client"

    def test_authorize_token(self):
        server = self.create_server()
        self.prepare_data()
        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "client_credentials"},
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert "access_token" in data
