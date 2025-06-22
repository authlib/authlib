from flask import json

from authlib.integrations.sqla_oauth2 import create_query_token_func
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server

query_token = create_query_token_func(db.session, Token)


class MyIntrospectionEndpoint(IntrospectionEndpoint):
    def check_permission(self, token, client, request):
        return True

    def query_token(self, token, token_type_hint):
        return query_token(token, token_type_hint)

    def introspect_token(self, token):
        user = db.session.get(User, token.user_id)
        return {
            "active": True,
            "client_id": token.client_id,
            "username": user.username,
            "scope": token.scope,
            "sub": user.get_user_id(),
            "aud": token.client_id,
            "iss": "https://server.example.com/",
            "exp": token.issued_at + token.expires_in,
            "iat": token.issued_at,
        }


class IntrospectTokenTest(TestCase):
    def prepare_data(self):
        app = self.app

        server = create_authorization_server(app)
        server.register_endpoint(MyIntrospectionEndpoint)

        @app.route("/oauth/introspect", methods=["POST"])
        def introspect_token():
            return server.create_endpoint_response("introspection")

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="introspect-client",
            client_secret="introspect-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "redirect_uris": ["http://a.b/c"],
            }
        )
        db.session.add(client)
        db.session.commit()

    def create_token(self):
        token = Token(
            user_id=1,
            client_id="introspect-client",
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
        rv = self.client.post("/oauth/introspect")
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = {"Authorization": "invalid token_string"}
        rv = self.client.post("/oauth/introspect", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("invalid-client", "introspect-secret")
        rv = self.client.post("/oauth/introspect", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        headers = self.create_basic_header("introspect-client", "invalid-secret")
        rv = self.client.post("/oauth/introspect", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_invalid_token(self):
        self.prepare_data()
        headers = self.create_basic_header("introspect-client", "introspect-secret")
        rv = self.client.post("/oauth/introspect", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token_type_hint": "refresh_token",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"

        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "a1",
                "token_type_hint": "unsupported_token_type",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "unsupported_token_type"

        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "invalid-token",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["active"] is False

        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "a1",
                "token_type_hint": "refresh_token",
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert resp["active"] is False

    def test_introspect_token_with_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("introspect-client", "introspect-secret")
        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "a1",
                "token_type_hint": "access_token",
            },
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp["client_id"] == "introspect-client"

    def test_introspect_token_without_hint(self):
        self.prepare_data()
        self.create_token()
        headers = self.create_basic_header("introspect-client", "introspect-secret")
        rv = self.client.post(
            "/oauth/introspect",
            data={
                "token": "a1",
            },
            headers=headers,
        )
        assert rv.status_code == 200
        resp = json.loads(rv.data)
        assert resp["client_id"] == "introspect-client"
