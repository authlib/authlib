import json

from authlib.integrations.django_oauth2 import RevocationEndpoint

from .models import Client
from .models import OAuth2Token
from .models import User
from .oauth2_server import TestCase

ENDPOINT_NAME = RevocationEndpoint.ENDPOINT_NAME


class RevocationEndpointTest(TestCase):
    def create_server(self):
        server = super().create_server()
        server.register_endpoint(RevocationEndpoint)
        return server

    def prepare_client(self):
        user = User(username="foo")
        user.save()
        client = Client(
            user_id=user.pk,
            client_id="client",
            client_secret="secret",
            token_endpoint_auth_method="client_secret_basic",
            default_redirect_uri="https://a.b",
        )
        client.save()

    def prepare_token(self, scope="profile", user_id=1):
        token = OAuth2Token(
            user_id=user_id,
            client_id="client",
            token_type="bearer",
            access_token="a1",
            refresh_token="r1",
            scope=scope,
            expires_in=3600,
        )
        token.save()

    def test_invalid_client(self):
        server = self.create_server()
        request = self.factory.post("/oauth/revoke")
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

        request = self.factory.post("/oauth/revoke", HTTP_AUTHORIZATION="invalid token")
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

        request = self.factory.post(
            "/oauth/revoke",
            HTTP_AUTHORIZATION=self.create_basic_auth("invalid", "secret"),
        )
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

        request = self.factory.post(
            "/oauth/revoke",
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "invalid"),
        )
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

    def test_invalid_token(self):
        server = self.create_server()
        self.prepare_client()
        self.prepare_token()
        auth_header = self.create_basic_auth("client", "secret")

        request = self.factory.post("/oauth/revoke", HTTP_AUTHORIZATION=auth_header)
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        data = json.loads(resp.content)
        assert data["error"] == "invalid_request"

        # case 1
        request = self.factory.post(
            "/oauth/revoke",
            data={"token": "invalid-token"},
            HTTP_AUTHORIZATION=auth_header,
        )
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        assert resp.status_code == 200

        # case 2
        request = self.factory.post(
            "/oauth/revoke",
            data={
                "token": "a1",
                "token_type_hint": "unsupported_token_type",
            },
            HTTP_AUTHORIZATION=auth_header,
        )
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        data = json.loads(resp.content)
        assert data["error"] == "unsupported_token_type"

        # case 3
        request = self.factory.post(
            "/oauth/revoke",
            data={
                "token": "a1",
                "token_type_hint": "refresh_token",
            },
            HTTP_AUTHORIZATION=auth_header,
        )
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        assert resp.status_code == 200

    def test_revoke_token_with_hint(self):
        self.prepare_client()
        self.prepare_token()
        self.revoke_token({"token": "a1", "token_type_hint": "access_token"})
        self.revoke_token({"token": "r1", "token_type_hint": "refresh_token"})

    def test_revoke_token_without_hint(self):
        self.prepare_client()
        self.prepare_token()
        self.revoke_token({"token": "a1"})
        self.revoke_token({"token": "r1"})

    def revoke_token(self, data):
        server = self.create_server()
        auth_header = self.create_basic_auth("client", "secret")

        request = self.factory.post(
            "/oauth/revoke",
            data=data,
            HTTP_AUTHORIZATION=auth_header,
        )
        resp = server.create_endpoint_response(ENDPOINT_NAME, request)
        assert resp.status_code == 200
