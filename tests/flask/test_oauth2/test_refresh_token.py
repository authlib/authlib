import time

from flask import json

from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and item.is_refresh_token_active():
            return item

    def authenticate_user(self, credential):
        return db.session.get(User, credential.user_id)

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.add(credential)
        db.session.commit()


class RefreshTokenTest(TestCase):
    def prepare_data(self, grant_type="refresh_token"):
        server = create_authorization_server(self.app)
        server.register_grant(RefreshTokenGrant)

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="refresh-client",
            client_secret="refresh-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "grant_types": [grant_type],
                "redirect_uris": ["http://localhost/authorized"],
            }
        )
        db.session.add(client)
        db.session.commit()

    def create_token(self, scope="profile", user_id=1):
        token = Token(
            user_id=user_id,
            client_id="refresh-client",
            token_type="bearer",
            access_token="a1",
            refresh_token="r1",
            scope=scope,
            expires_in=3600,
        )
        db.session.add(token)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "foo",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("invalid-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "foo",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("refresh-client", "invalid-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "foo",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_invalid_refresh_token(self):
        self.prepare_data()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"
        assert "Missing" in resp["error_description"]

        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "foo",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_invalid_scope(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "invalid",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_invalid_scope_none(self):
        self.prepare_data()
        self.create_token(scope=None)
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "invalid",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_invalid_user(self):
        self.prepare_data()
        self.create_token(user_id=5)
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

    def test_invalid_grant_type(self):
        self.prepare_data(grant_type="invalid")
        self.create_token()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "unauthorized_client"

    def test_authorize_token_no_scope(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_authorize_token_scope(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_revoke_old_credential(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
                "scope": "profile",
            },
            headers=headers,
        )
        assert rv.status_code == 400
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_token_generator(self):
        m = "tests.flask.test_oauth2.oauth2_server:token_generator"
        self.app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})

        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("refresh-client", "refresh-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "r1",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert "r-refresh_token.1." in resp["access_token"]
