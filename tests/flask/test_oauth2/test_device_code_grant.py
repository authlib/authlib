import time

from flask import json

from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
)
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _DeviceCodeGrant
from authlib.oauth2.rfc8628 import DeviceCredentialDict

from .models import Client
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server

device_credentials = {
    "valid-device": {
        "client_id": "client",
        "expires_in": 1800,
        "user_code": "code",
    },
    "expired-token": {
        "client_id": "client",
        "expires_in": -100,
        "user_code": "none",
    },
    "invalid-client": {
        "client_id": "invalid",
        "expires_in": 1800,
        "user_code": "none",
    },
    "denied-code": {
        "client_id": "client",
        "expires_in": 1800,
        "user_code": "denied",
    },
    "grant-code": {
        "client_id": "client",
        "expires_in": 1800,
        "user_code": "code",
    },
    "pending-code": {
        "client_id": "client",
        "expires_in": 1800,
        "user_code": "none",
    },
}


class DeviceCodeGrant(_DeviceCodeGrant):
    def query_device_credential(self, device_code):
        data = device_credentials.get(device_code)
        if not data:
            return None

        now = int(time.time())
        data["expires_at"] = now + data["expires_in"]
        data["device_code"] = device_code
        data["scope"] = "profile"
        data["interval"] = 5
        data["verification_uri"] = "https://example.com/activate"
        return DeviceCredentialDict(data)

    def query_user_grant(self, user_code):
        if user_code == "code":
            return db.session.get(User, 1), True
        if user_code == "denied":
            return db.session.get(User, 1), False
        return None

    def should_slow_down(self, credential):
        return False


class DeviceCodeGrantTest(TestCase):
    def create_server(self):
        server = create_authorization_server(self.app)
        server.register_grant(DeviceCodeGrant)
        self.server = server
        return server

    def prepare_data(self, grant_type=DeviceCodeGrant.GRANT_TYPE):
        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="client",
            client_secret="secret",
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["http://localhost/authorized"],
                "scope": "profile",
                "grant_types": [grant_type],
                "token_endpoint_auth_method": "none",
            }
        )
        db.session.add(client)
        db.session.commit()

    def test_invalid_request(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "client_id": "test",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "missing",
                "client_id": "client",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_unauthorized_client(self):
        self.create_server()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "valid-device",
                "client_id": "invalid",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        self.prepare_data(grant_type="password")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "valid-device",
                "client_id": "client",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "unauthorized_client"

    def test_invalid_client(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "invalid-client",
                "client_id": "invalid",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_expired_token(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "expired-token",
                "client_id": "client",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "expired_token"

    def test_denied_by_user(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "denied-code",
                "client_id": "client",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "access_denied"

    def test_authorization_pending(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "pending-code",
                "client_id": "client",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "authorization_pending"

    def test_get_access_token(self):
        self.create_server()
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": "grant-code",
                "client_id": "client",
            },
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp


class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
    def get_verification_uri(self):
        return "https://example.com/activate"

    def save_device_credential(self, client_id, scope, data):
        pass


class DeviceAuthorizationEndpointTest(TestCase):
    def create_server(self):
        server = create_authorization_server(self.app)
        server.register_endpoint(DeviceAuthorizationEndpoint)
        self.server = server

        @self.app.route("/device_authorize", methods=["POST"])
        def device_authorize():
            name = DeviceAuthorizationEndpoint.ENDPOINT_NAME
            return server.create_endpoint_response(name)

        return server

    def test_missing_client_id(self):
        self.create_server()
        rv = self.client.post("/device_authorize", data={"scope": "profile"})
        assert rv.status_code == 401
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_create_authorization_response(self):
        self.create_server()
        client = Client(
            user_id=1,
            client_id="client",
            client_secret="secret",
        )
        db.session.add(client)
        db.session.commit()
        rv = self.client.post(
            "/device_authorize",
            data={
                "client_id": "client",
            },
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert "device_code" in resp
        assert "user_code" in resp
        assert resp["verification_uri"] == "https://example.com/activate"
        assert (
            resp["verification_uri_complete"]
            == "https://example.com/activate?user_code=" + resp["user_code"]
        )
