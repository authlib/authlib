import time

from flask import current_app
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import url_encode
from authlib.common.urls import urlparse
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import exists_nonce
from .models import save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class OpenIDCode(_OpenIDCode):
    def get_jwt_config(self, grant):
        key = current_app.config["OAUTH2_JWT_KEY"]
        alg = current_app.config["OAUTH2_JWT_ALG"]
        iss = current_app.config["OAUTH2_JWT_ISS"]
        return dict(key=key, alg=alg, iss=iss, exp=3600)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


class BaseTestCase(TestCase):
    def config_app(self):
        self.app.config.update(
            {
                "OAUTH2_JWT_ISS": "Authlib",
                "OAUTH2_JWT_KEY": "secret",
                "OAUTH2_JWT_ALG": "HS256",
            }
        )

    def prepare_data(self, require_nonce=False):
        self.config_app()
        server = create_authorization_server(self.app)
        server.register_grant(
            AuthorizationCodeGrant, [OpenIDCode(require_nonce=require_nonce)]
        )

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

        client = Client(
            user_id=user.id,
            client_id="code-client",
            client_secret="code-secret",
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["https://a.b"],
                "scope": "openid profile address",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }
        )
        db.session.add(client)
        db.session.commit()


class OpenIDCodeTest(BaseTestCase):
    def test_authorize_token(self):
        self.prepare_data()
        auth_request_time = time.time()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": "code-client",
                "state": "bar",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["state"] == "bar"

        code = params["code"]
        headers = self.create_basic_header("code-client", "code-secret")
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

        claims = jwt.decode(
            resp["id_token"],
            "secret",
            claims_cls=CodeIDToken,
            claims_options={"iss": {"value": "Authlib"}},
        )
        claims.validate()
        assert claims["auth_time"] >= int(auth_request_time)
        assert claims["acr"] == "urn:mace:incommon:iap:silver"
        assert claims["amr"] == ["pwd", "otp"]

    def test_pure_code_flow(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": "code-client",
                "state": "bar",
                "scope": "profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["state"] == "bar"

        code = params["code"]
        headers = self.create_basic_header("code-client", "code-secret")
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
        assert "id_token" not in resp

    def test_require_nonce(self):
        self.prepare_data(require_nonce=True)
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": "code-client",
                "user_id": "1",
                "state": "bar",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
            },
        )
        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["error"] == "invalid_request"
        assert params["error_description"] == "Missing 'nonce' in request."

    def test_nonce_replay(self):
        self.prepare_data()
        data = {
            "response_type": "code",
            "client_id": "code-client",
            "user_id": "1",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://a.b",
        }
        rv = self.client.post("/oauth/authorize", data=data)
        assert "code=" in rv.location

        rv = self.client.post("/oauth/authorize", data=data)
        assert "error=" in rv.location

    def test_prompt(self):
        self.prepare_data()
        params = [
            ("response_type", "code"),
            ("client_id", "code-client"),
            ("state", "bar"),
            ("nonce", "abc"),
            ("scope", "openid profile"),
            ("redirect_uri", "https://a.b"),
        ]
        query = url_encode(params)
        rv = self.client.get("/oauth/authorize?" + query)
        assert rv.data == b"login"

        query = url_encode(params + [("user_id", "1")])
        rv = self.client.get("/oauth/authorize?" + query)
        assert rv.data == b"ok"

        query = url_encode(params + [("prompt", "login")])
        rv = self.client.get("/oauth/authorize?" + query)
        assert rv.data == b"login"

        query = url_encode(params + [("user_id", "1"), ("prompt", "login")])
        rv = self.client.get("/oauth/authorize?" + query)
        assert rv.data == b"login"

    def test_prompt_none_not_logged(self):
        self.prepare_data()
        params = [
            ("response_type", "code"),
            ("client_id", "code-client"),
            ("state", "bar"),
            ("nonce", "abc"),
            ("scope", "openid profile"),
            ("redirect_uri", "https://a.b"),
            ("prompt", "none"),
        ]
        query = url_encode(params)
        rv = self.client.get("/oauth/authorize?" + query)

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["error"] == "login_required"
        assert params["state"] == "bar"


class RSAOpenIDCodeTest(BaseTestCase):
    def config_app(self):
        self.app.config.update(
            {
                "OAUTH2_JWT_ISS": "Authlib",
                "OAUTH2_JWT_KEY": read_file_path("jwk_private.json"),
                "OAUTH2_JWT_ALG": "RS256",
            }
        )

    def get_validate_key(self):
        return read_file_path("jwk_public.json")

    def test_authorize_token(self):
        # generate refresh token
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": "code-client",
                "state": "bar",
                "scope": "openid profile",
                "redirect_uri": "https://a.b",
                "user_id": "1",
            },
        )
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        assert params["state"] == "bar"

        code = params["code"]
        headers = self.create_basic_header("code-client", "code-secret")
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

        claims = jwt.decode(
            resp["id_token"],
            self.get_validate_key(),
            claims_cls=CodeIDToken,
            claims_options={"iss": {"value": "Authlib"}},
        )
        claims.validate()


class JWKSOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        self.app.config.update(
            {
                "OAUTH2_JWT_ISS": "Authlib",
                "OAUTH2_JWT_KEY": read_file_path("jwks_private.json"),
                "OAUTH2_JWT_ALG": "PS256",
            }
        )

    def get_validate_key(self):
        return read_file_path("jwks_public.json")


class ECOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        self.app.config.update(
            {
                "OAUTH2_JWT_ISS": "Authlib",
                "OAUTH2_JWT_KEY": read_file_path("secp521r1-private.json"),
                "OAUTH2_JWT_ALG": "ES512",
            }
        )

    def get_validate_key(self):
        return read_file_path("secp521r1-public.json")


class PEMOpenIDCodeTest(RSAOpenIDCodeTest):
    def config_app(self):
        self.app.config.update(
            {
                "OAUTH2_JWT_ISS": "Authlib",
                "OAUTH2_JWT_KEY": read_file_path("rsa_private.pem"),
                "OAUTH2_JWT_ALG": "RS256",
            }
        )

    def get_validate_key(self):
        return read_file_path("rsa_public.pem")
