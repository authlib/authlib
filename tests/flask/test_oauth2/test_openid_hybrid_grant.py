from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core.grants import OpenIDHybridGrant as _OpenIDHybridGrant

from .models import Client
from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import exists_nonce
from .models import save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server

JWT_CONFIG = {"iss": "Authlib", "key": "secret", "alg": "HS256", "exp": 3600}


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class OpenIDCode(_OpenIDCode):
    def get_jwt_config(self, grant):
        return dict(JWT_CONFIG)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


class OpenIDHybridGrant(_OpenIDHybridGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)

    def get_jwt_config(self):
        return dict(JWT_CONFIG)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


class OpenIDCodeTest(TestCase):
    def prepare_data(self):
        server = create_authorization_server(self.app)
        server.register_grant(OpenIDHybridGrant)
        server.register_grant(AuthorizationCodeGrant, [OpenIDCode()])

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id="hybrid-client",
            client_secret="hybrid-secret",
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["https://a.b"],
                "scope": "openid profile address",
                "response_types": [
                    "code id_token",
                    "code token",
                    "code id_token token",
                ],
                "grant_types": ["authorization_code"],
            }
        )
        db.session.add(client)
        db.session.commit()

    def validate_claims(self, id_token, params):
        claims = jwt.decode(
            id_token, "secret", claims_cls=HybridIDToken, claims_params=params
        )
        claims.validate()

    def test_invalid_client_id(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code token",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "invalid-client",
                "response_type": "code token",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        resp = json.loads(rv.data)
        assert resp["error"] == "invalid_client"

    def test_require_nonce(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code token",
                "scope": "openid profile",
                "state": "bar",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "error=invalid_request" in rv.location
        assert "nonce" in rv.location

    def test_invalid_response_type(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code id_token invalid",
                "state": "bar",
                "nonce": "abc",
                "scope": "profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["error"] == "unsupported_response_type"

    def test_invalid_scope(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code id_token",
                "state": "bar",
                "nonce": "abc",
                "scope": "profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "error=invalid_scope" in rv.location

    def test_access_denied(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code token",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
            },
        )
        assert "error=access_denied" in rv.location

    def test_code_access_token(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code token",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location
        assert "access_token=" in rv.location
        assert "id_token=" not in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        assert params["state"] == "bar"

        code = params["code"]
        headers = self.create_basic_header("hybrid-client", "hybrid-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "https://a.b",
                "code": code,
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert "id_token" in resp

    def test_code_id_token(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code id_token",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location
        assert "id_token=" in rv.location
        assert "access_token=" not in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        assert params["state"] == "bar"

        params["nonce"] = "abc"
        params["client_id"] = "hybrid-client"
        self.validate_claims(params["id_token"], params)

        code = params["code"]
        headers = self.create_basic_header("hybrid-client", "hybrid-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "https://a.b",
                "code": code,
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert "id_token" in resp

    def test_code_id_token_access_token(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code id_token token",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location
        assert "id_token=" in rv.location
        assert "access_token=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        assert params["state"] == "bar"
        self.validate_claims(params["id_token"], params)

        code = params["code"]
        headers = self.create_basic_header("hybrid-client", "hybrid-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "https://a.b",
                "code": code,
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp
        assert "id_token" in resp

    def test_response_mode_query(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code id_token token",
                "response_mode": "query",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location
        assert "id_token=" in rv.location
        assert "access_token=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["state"] == "bar"

    def test_response_mode_form_post(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "client_id": "hybrid-client",
                "response_type": "code id_token token",
                "response_mode": "form_post",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert b'name="code"' in rv.data
        assert b'name="id_token"' in rv.data
        assert b'name="access_token"' in rv.data
