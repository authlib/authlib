from flask import json

import authlib.oidc.core as oidc_core
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.jose import jwt
from tests.util import read_file_path

from .models import Client
from .models import Token
from .models import User
from .models import db
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class UserInfoEndpointTest(TestCase):
    def prepare_data(
        self,
        token_scope="openid",
        userinfo_signed_response_alg=None,
        userinfo_encrypted_response_alg=None,
        userinfo_encrypted_response_enc=None,
    ):
        app = self.app
        server = create_authorization_server(app)

        class UserInfoEndpoint(oidc_core.UserInfoEndpoint):
            def get_issuer(self) -> str:
                return "https://auth.example"

            def generate_user_info(self, user, scope):
                return user.generate_user_info().filter(scope)

            def resolve_private_key(self):
                return read_file_path("jwks_private.json")

        BearerTokenValidator = create_bearer_token_validator(db.session, Token)
        resource_protector = ResourceProtector()
        resource_protector.register_token_validator(BearerTokenValidator())
        server.register_endpoint(
            UserInfoEndpoint(resource_protector=resource_protector)
        )

        @app.route("/oauth/userinfo", methods=["GET", "POST"])
        def userinfo():
            return server.create_endpoint_response("userinfo")

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="userinfo-client",
            client_secret="userinfo-secret",
        )
        client.set_client_metadata(
            {
                "scope": "profile",
                "redirect_uris": ["http://localhost/authorized"],
                "userinfo_signed_response_alg": userinfo_signed_response_alg,
                "userinfo_encrypted_response_alg": userinfo_encrypted_response_alg,
                "userinfo_encrypted_response_enc": userinfo_encrypted_response_enc,
            }
        )
        db.session.add(client)
        db.session.commit()

        token = Token(
            user_id=1,
            client_id="userinfo-client",
            token_type="bearer",
            access_token="access-token",
            refresh_token="r1",
            scope=token_scope,
            expires_in=3600,
        )
        db.session.add(token)
        db.session.commit()

    def test_get(self):
        """The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231].
        The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750]."""

        self.prepare_data("openid profile email address phone")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        assert rv.headers["Content-Type"] == "application/json"

        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
            "address": {
                "country": "USA",
                "formatted": "742 Evergreen Terrace, Springfield",
                "locality": "Springfield",
                "postal_code": "1245",
                "region": "Unknown",
                "street_address": "742 Evergreen Terrace",
            },
            "birthdate": "2000-12-01",
            "email": "janedoe@example.com",
            "email_verified": True,
            "family_name": "Doe",
            "gender": "female",
            "given_name": "Jane",
            "locale": "fr-FR",
            "middle_name": "Middle",
            "name": "foo",
            "nickname": "Jany",
            "phone_number": "+1 (425) 555-1212",
            "phone_number_verified": False,
            "picture": "https://example.com/janedoe/me.jpg",
            "preferred_username": "j.doe",
            "profile": "https://example.com/janedoe",
            "updated_at": 1745315119,
            "website": "https://example.com",
            "zoneinfo": "Europe/Paris",
        }

    def test_post(self):
        """The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231].
        The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750]."""

        self.prepare_data("openid profile email address phone")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.post("/oauth/userinfo", headers=headers)
        assert rv.headers["Content-Type"] == "application/json"

        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
            "address": {
                "country": "USA",
                "formatted": "742 Evergreen Terrace, Springfield",
                "locality": "Springfield",
                "postal_code": "1245",
                "region": "Unknown",
                "street_address": "742 Evergreen Terrace",
            },
            "birthdate": "2000-12-01",
            "email": "janedoe@example.com",
            "email_verified": True,
            "family_name": "Doe",
            "gender": "female",
            "given_name": "Jane",
            "locale": "fr-FR",
            "middle_name": "Middle",
            "name": "foo",
            "nickname": "Jany",
            "phone_number": "+1 (425) 555-1212",
            "phone_number_verified": False,
            "picture": "https://example.com/janedoe/me.jpg",
            "preferred_username": "j.doe",
            "profile": "https://example.com/janedoe",
            "updated_at": 1745315119,
            "website": "https://example.com",
            "zoneinfo": "Europe/Paris",
        }

    def test_no_token(self):
        self.prepare_data()
        rv = self.client.post("/oauth/userinfo")
        resp = json.loads(rv.data)
        assert resp["error"] == "missing_authorization"

    def test_bad_token(self):
        self.prepare_data()
        headers = {"Authorization": "invalid token_string"}
        rv = self.client.post("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "unsupported_token_type"

    def test_token_has_bad_scope(self):
        """Test that tokens without 'openid' scope cannot access the userinfo endpoint."""

        self.prepare_data(token_scope="foobar")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.post("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp["error"] == "insufficient_scope"

    def test_scope_minimum(self):
        self.prepare_data("openid")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
        }

    def test_scope_profile(self):
        self.prepare_data("openid profile")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
            "birthdate": "2000-12-01",
            "family_name": "Doe",
            "gender": "female",
            "given_name": "Jane",
            "locale": "fr-FR",
            "middle_name": "Middle",
            "name": "foo",
            "nickname": "Jany",
            "picture": "https://example.com/janedoe/me.jpg",
            "preferred_username": "j.doe",
            "profile": "https://example.com/janedoe",
            "updated_at": 1745315119,
            "website": "https://example.com",
            "zoneinfo": "Europe/Paris",
        }

    def test_scope_address(self):
        self.prepare_data("openid address")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
            "address": {
                "country": "USA",
                "formatted": "742 Evergreen Terrace, Springfield",
                "locality": "Springfield",
                "postal_code": "1245",
                "region": "Unknown",
                "street_address": "742 Evergreen Terrace",
            },
        }

    def test_scope_email(self):
        self.prepare_data("openid email")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
            "email": "janedoe@example.com",
            "email_verified": True,
        }

    def test_scope_phone(self):
        self.prepare_data("openid phone")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        resp = json.loads(rv.data)
        assert resp == {
            "sub": "1",
            "phone_number": "+1 (425) 555-1212",
            "phone_number_verified": False,
        }

    def test_scope_signed_unsecured(self):
        """When userinfo_signed_response_alg is set as client metadata, the userinfo response must be a JWT."""
        self.prepare_data("openid email", userinfo_signed_response_alg="none")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        assert rv.headers["Content-Type"] == "application/jwt"

        claims = jwt.decode(rv.data, None)
        assert claims == {
            "sub": "1",
            "iss": "https://auth.example",
            "aud": "userinfo-client",
            "email": "janedoe@example.com",
            "email_verified": True,
        }

    def test_scope_signed_secured(self):
        """When userinfo_signed_response_alg is set as client metadata and not none, the userinfo response must be signed."""
        self.prepare_data("openid email", userinfo_signed_response_alg="RS256")
        headers = {"Authorization": "Bearer access-token"}
        rv = self.client.get("/oauth/userinfo", headers=headers)
        assert rv.headers["Content-Type"] == "application/jwt"

        pub_key = read_file_path("jwks_public.json")
        claims = jwt.decode(rv.data, pub_key)
        assert claims == {
            "sub": "1",
            "iss": "https://auth.example",
            "aud": "userinfo-client",
            "email": "janedoe@example.com",
            "email_verified": True,
        }
