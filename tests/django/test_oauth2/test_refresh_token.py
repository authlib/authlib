import json
import time

from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant

from .models import Client
from .models import OAuth2Token
from .models import User
from .oauth2_server import TestCase


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        try:
            item = OAuth2Token.objects.get(refresh_token=refresh_token)
            if item.is_refresh_token_active():
                return item
        except OAuth2Token.DoesNotExist:
            return None

    def authenticate_user(self, credential):
        return credential.user

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        credential.save()
        return credential


class RefreshTokenTest(TestCase):
    def create_server(self):
        server = super().create_server()
        server.register_grant(RefreshTokenGrant)
        return server

    def prepare_client(self, grant_type="refresh_token", scope=""):
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
        self.prepare_client()
        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "foo"},
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "foo"},
            HTTP_AUTHORIZATION=self.create_basic_auth("invalid", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 401
        data = json.loads(resp.content)
        assert data["error"] == "invalid_client"

    def test_invalid_refresh_token(self):
        self.prepare_client()
        server = self.create_server()
        auth_header = self.create_basic_auth("client", "secret")
        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "refresh_token"},
            HTTP_AUTHORIZATION=auth_header,
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 400
        data = json.loads(resp.content)
        assert data["error"] == "invalid_request"
        assert "Missing" in data["error_description"]

        request = self.factory.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "invalid"},
            HTTP_AUTHORIZATION=auth_header,
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 400
        data = json.loads(resp.content)
        assert data["error"] == "invalid_grant"

    def test_invalid_scope(self):
        server = self.create_server()
        server.scopes_supported = ["profile"]
        self.prepare_client()
        self.prepare_token()
        request = self.factory.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "invalid",
            },
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 400
        data = json.loads(resp.content)
        assert data["error"] == "invalid_scope"

    def test_authorize_tno_scope(self):
        server = self.create_server()
        self.prepare_client()
        self.prepare_token()

        request = self.factory.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
            },
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert "access_token" in data

    def test_authorize_token_scope(self):
        server = self.create_server()
        self.prepare_client()
        self.prepare_token()

        request = self.factory.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert "access_token" in data

    def test_revoke_old_token(self):
        server = self.create_server()
        self.prepare_client()
        self.prepare_token()

        request = self.factory.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            HTTP_AUTHORIZATION=self.create_basic_auth("client", "secret"),
        )
        resp = server.create_token_response(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert "access_token" in data

        resp = server.create_token_response(request)
        assert resp.status_code == 400
