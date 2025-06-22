import pytest
from flask import json

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge as _CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .models import Client
from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class AuthorizationCodeGrant(CodeGrantMixin, grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class CodeChallenge(_CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ["plain", "S256", "S128"]


class CodeChallengeTest(TestCase):
    def prepare_data(self, token_endpoint_auth_method="none"):
        server = create_authorization_server(self.app)
        server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

        client_secret = ""
        if token_endpoint_auth_method != "none":
            client_secret = "code-secret"

        client = Client(
            user_id=user.id,
            client_id="code-client",
            client_secret=client_secret,
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["https://a.b"],
                "scope": "profile address",
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }
        )
        self.authorize_url = "/oauth/authorize?response_type=code&client_id=code-client"
        db.session.add(client)
        db.session.commit()

    def test_missing_code_challenge(self):
        self.prepare_data()
        rv = self.client.get(self.authorize_url + "&code_challenge_method=plain")
        assert "Missing" in rv.location

    def test_has_code_challenge(self):
        self.prepare_data()
        rv = self.client.get(
            self.authorize_url
            + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
        )
        assert rv.data == b"ok"

    def test_invalid_code_challenge(self):
        self.prepare_data()
        rv = self.client.get(
            self.authorize_url + "&code_challenge=abc&code_challenge_method=plain"
        )
        assert "Invalid" in rv.location

    def test_invalid_code_challenge_method(self):
        self.prepare_data()
        suffix = "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s&code_challenge_method=invalid"
        rv = self.client.get(self.authorize_url + suffix)
        assert "Unsupported" in rv.location

    def test_supported_code_challenge_method(self):
        self.prepare_data()
        suffix = "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s&code_challenge_method=plain"
        rv = self.client.get(self.authorize_url + suffix)
        assert rv.data == b"ok"

    def test_trusted_client_without_code_challenge(self):
        self.prepare_data("client_secret_basic")
        rv = self.client.get(self.authorize_url)
        assert rv.data == b"ok"

        rv = self.client.post(self.authorize_url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))

        code = params["code"]
        headers = self.create_basic_header("code-client", "code-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_missing_code_verifier(self):
        self.prepare_data()
        url = (
            self.authorize_url
            + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
        )
        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "code-client",
            },
        )
        resp = json.loads(rv.data)
        assert "Missing" in resp["error_description"]

    def test_trusted_client_missing_code_verifier(self):
        self.prepare_data("client_secret_basic")
        url = (
            self.authorize_url
            + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
        )
        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        headers = self.create_basic_header("code-client", "code-secret")
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
            },
            headers=headers,
        )
        resp = json.loads(rv.data)
        assert "Missing" in resp["error_description"]

    def test_plain_code_challenge_invalid(self):
        self.prepare_data()
        url = (
            self.authorize_url
            + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
        )
        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": "bar",
                "client_id": "code-client",
            },
        )
        resp = json.loads(rv.data)
        assert "Invalid" in resp["error_description"]

    def test_plain_code_challenge_failed(self):
        self.prepare_data()
        url = (
            self.authorize_url
            + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
        )
        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": generate_token(48),
                "client_id": "code-client",
            },
        )
        resp = json.loads(rv.data)
        assert "failed" in resp["error_description"]

    def test_plain_code_challenge_success(self):
        self.prepare_data()
        code_verifier = generate_token(48)
        url = self.authorize_url + "&code_challenge=" + code_verifier
        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "client_id": "code-client",
            },
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_s256_code_challenge_success(self):
        self.prepare_data()
        code_verifier = generate_token(48)
        code_challenge = create_s256_code_challenge(code_verifier)
        url = self.authorize_url + "&code_challenge=" + code_challenge
        url += "&code_challenge_method=S256"

        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        rv = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "client_id": "code-client",
            },
        )
        resp = json.loads(rv.data)
        assert "access_token" in resp

    def test_not_implemented_code_challenge_method(self):
        self.prepare_data()
        url = (
            self.authorize_url
            + "&code_challenge=Zhs2POMonIVVHZteWfoU7cSXQSm0YjghikFGJSDI2_s"
        )
        url += "&code_challenge_method=S128"

        rv = self.client.post(url, data={"user_id": "1"})
        assert "code=" in rv.location

        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        code = params["code"]
        with pytest.raises(RuntimeError):
            self.client.post(
                "/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": generate_token(48),
                    "client_id": "code-client",
                },
            )
