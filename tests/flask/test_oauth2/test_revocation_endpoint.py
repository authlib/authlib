from flask import json

from authlib.integrations.sqla_oauth2 import create_revocation_endpoint

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server

RevocationEndpoint = create_revocation_endpoint(db.session, Token)


class RevokeTokenTest(TestCase):
    def prepare_data(self):
        app = self.app
        server = create_authorization_server(app)
        server.register_endpoint(RevocationEndpoint)

        @app.route("/oauth/revoke", methods=["POST"])
        def revoke_token():
            return server.create_endpoint_response("revocation")

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="revoke-client",
            client_secret="revoke-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "redirect_uris": ["http://localhost/authorized"],
            }
        )
        db.session.add(client)
        db.session.commit()

    def create_token(self):
        token = Token(
            user_id=1,
            client_id="revoke-client",
            token_type="bearer",
            access_token="a1",
            refresh_token="r1",
            scope="profile",
            expires_in=3600,
        )
        db.session.add(token)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post("/oauth/revoke")
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = {"Authorization": "invalid token_string"}
        rv = self.client.post("/oauth/revoke", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("invalid-client", "revoke-secret")
        rv = self.client.post("/oauth/revoke", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("revoke-client", "invalid-secret")
        rv = self.client.post("/oauth/revoke", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_invalid_token(self):
        self.prepare_data()
        headers = self.create_basic_header("revoke-client", "revoke-secret")
        rv = self.client.post("/oauth/revoke", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "invalid-token",
            },
            headers=headers,
        )
        assert rv.status_code == 200

        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "a1",
                "token_type_hint": "unsupported_token_type",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "unsupported_token_type"

        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "a1",
                "token_type_hint": "refresh_token",
            },
            headers=headers,
        )
        assert rv.status_code == 200

    def test_revoke_token_with_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("revoke-client", "revoke-secret")
        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "a1",
                "token_type_hint": "access_token",
            },
            headers=headers,
        )
        assert rv.status_code == 200

    def test_revoke_token_without_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("revoke-client", "revoke-secret")
        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "a1",
            },
            headers=headers,
        )
        assert rv.status_code == 200

    def test_revoke_token_bound_to_client(self):
        self.prepare_data()
        self.create_token()

        client2 = Client(
            user_id=1,
            client_id="revoke-client-2",
            client_secret="revoke-secret-2",
        )
        client2.set_client_metadata(
            {
                "scope": "profile",
                "redirect_uris": ["http://localhost/authorized"],
            }
        )
        db.session.add(client2)
        db.session.commit()

        headers = self.create_basic_header("revoke-client-2", "revoke-secret-2")
        rv = self.client.post(
            "/oauth/revoke",
            data={
                "token": "a1",
            },
            headers=headers,
        )
        assert rv.status_code == 400
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"
