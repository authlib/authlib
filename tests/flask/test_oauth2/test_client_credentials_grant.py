from flask import json

from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant

from .models import Client
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class ClientCredentialsTest(TestCase):
    def prepare_data(self, grant_type="client_credentials"):
        server = create_authorization_server(self.app)
        server.register_grant(ClientCredentialsGrant)
        self.server = server

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="credential-client",
            client_secret="credential-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "redirect_uris": ["http://localhost/authorized"],
                "grant_types": [grant_type],
            }
        )
        db.session.add(client)
        db.session.commit()

    def test_invalid_client(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("credential-client", "invalid-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_invalid_grant_type(self):
        self.prepare_data(grant_type="invalid")
        headers = self.create_basic_header("credential-client", "credential-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "unauthorized_client"

    def test_invalid_scope(self):
        self.prepare_data()
        self.server.scopes_supported = ["profile"]
        headers = self.create_basic_header("credential-client", "credential-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "scope": "invalid",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_scope"

    def test_authorize_token(self):
        self.prepare_data()
        headers = self.create_basic_header("credential-client", "credential-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_token_generator(self):
        m = "tests.flask.test_oauth2.oauth2_server:token_generator"
        self.app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})

        self.prepare_data()
        headers = self.create_basic_header("credential-client", "credential-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert "c-client_credentials." in resp["access_token"]
