from flask import json

from authlib.oauth2.rfc7523 import JWTBearerGrant as _JWTBearerGrant
from authlib.oauth2.rfc7523 import JWTBearerTokenGenerator
from tests.util import read_file_path

from .models import Client
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class JWTBearerGrant(_JWTBearerGrant):
    def resolve_issuer_client(self, issuer):
        return Client.query.filter_by(client_id=issuer).first()

    def resolve_client_key(self, client, headers, payload):
        keys = {"1": "foo", "2": "bar"}
        return keys[headers["kid"]]

    def authenticate_user(self, subject):
        return None

    def has_granted_permission(self, client, user):
        return True


class JWTBearerGrantTest(TestCase):
    def prepare_data(self, grant_type=None, token_generator=None):
        server = create_authorization_server(self.app)
        server.register_grant(JWTBearerGrant)

        if token_generator:
            server.register_token_generator(JWTBearerGrant.GRANT_TYPE, token_generator)

        if grant_type is None:
            grant_type = JWTBearerGrant.GRANT_TYPE

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="jwt-client",
            client_secret="jwt-secret",
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

    def test_missing_assertion(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/token", data={"grant_type": JWTBearerGrant.GRANT_TYPE}
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_request"
        assert "assertion" in resp["error_description"]

    def test_invalid_assertion(self):
        self.prepare_data()
        assertion = JWTBearerGrant.sign(
            "foo",
            issuer="jwt-client",
            audience="https://i.b/token",
            subject="none",
            header={"alg": "HS256", "kid": "1"},
        )
        rv = self.client.post(
            "/oauth/token",
            data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_grant"

    def test_authorize_token(self):
        self.prepare_data()
        assertion = JWTBearerGrant.sign(
            "foo",
            issuer="jwt-client",
            audience="https://i.b/token",
            subject=None,
            header={"alg": "HS256", "kid": "1"},
        )
        rv = self.client.post(
            "/oauth/token",
            data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_unauthorized_client(self):
        self.prepare_data("password")
        assertion = JWTBearerGrant.sign(
            "bar",
            issuer="jwt-client",
            audience="https://i.b/token",
            subject=None,
            header={"alg": "HS256", "kid": "2"},
        )
        rv = self.client.post(
            "/oauth/token",
            data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "unauthorized_client"

    def test_token_generator(self):
        m = "tests.flask.test_oauth2.oauth2_server:token_generator"
        self.app.config.update({"OAUTH2_ACCESS_TOKEN_GENERATOR": m})
        self.prepare_data()
        assertion = JWTBearerGrant.sign(
            "foo",
            issuer="jwt-client",
            audience="https://i.b/token",
            subject=None,
            header={"alg": "HS256", "kid": "1"},
        )
        rv = self.client.post(
            "/oauth/token",
            data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert "j-" in resp["access_token"]

    def test_jwt_bearer_token_generator(self):
        private_key = read_file_path("jwks_private.json")
        self.prepare_data(token_generator=JWTBearerTokenGenerator(private_key))
        assertion = JWTBearerGrant.sign(
            "foo",
            issuer="jwt-client",
            audience="https://i.b/token",
            subject=None,
            header={"alg": "HS256", "kid": "1"},
        )
        rv = self.client.post(
            "/oauth/token",
            data={"grant_type": JWTBearerGrant.GRANT_TYPE, "assertion": assertion},
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert resp["access_token"].count(".") == 2
