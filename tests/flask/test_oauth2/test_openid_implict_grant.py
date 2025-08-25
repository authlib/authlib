from flask import current_app

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.jose import JsonWebToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core.grants import OpenIDImplicitGrant as _OpenIDImplicitGrant

from .models import Client
from .models import User
from .models import db
from .models import exists_nonce
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class OpenIDImplicitGrant(_OpenIDImplicitGrant):
    def get_jwt_config(self):
        alg = current_app.config.get("OAUTH2_JWT_ALG", "HS256")
        return dict(key="secret", alg=alg, iss="Authlib", exp=3600)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)


class ImplicitTest(TestCase):
    def prepare_data(self, id_token_signed_response_alg=None):
        server = create_authorization_server(self.app)
        server.register_grant(OpenIDImplicitGrant)

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="implicit-client",
            client_secret="",
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["https://a.b/c"],
                "scope": "openid profile",
                "token_endpoint_auth_method": "none",
                "response_types": ["id_token", "id_token token"],
                "id_token_signed_response_alg": id_token_signed_response_alg,
            }
        )
        self.authorize_url = (
            "/oauth/authorize?response_type=token&client_id=implicit-client"
        )
        db.session.add(client)
        db.session.commit()

    def validate_claims(self, id_token, params, alg="HS256"):
        jwt = JsonWebToken([alg])
        claims = jwt.decode(
            id_token, "secret", claims_cls=ImplicitIDToken, claims_params=params
        )
        claims.validate()
        return claims

    def test_consent_view(self):
        self.prepare_data()
        rv = self.client.get(
            add_params_to_uri(
                "/oauth/authorize",
                {
                    "response_type": "id_token",
                    "client_id": "implicit-client",
                    "scope": "openid profile",
                    "state": "foo",
                    "redirect_uri": "https://a.b/c",
                    "user_id": "1",
                },
            )
        )
        assert "error=invalid_request" in rv.location
        assert "nonce" in rv.location

    def test_require_nonce(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "bar",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
            },
        )
        assert "error=invalid_request" in rv.location
        assert "nonce" in rv.location

    def test_missing_openid_in_scope(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token token",
                "client_id": "implicit-client",
                "scope": "profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
            },
        )
        assert "error=invalid_scope" in rv.location

    def test_denied(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://a.b/c",
            },
        )
        assert "error=access_denied" in rv.location

    def test_authorize_access_token(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token token",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
            },
        )
        assert "access_token=" in rv.location
        assert "id_token=" in rv.location
        assert "state=bar" in rv.location
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.validate_claims(params["id_token"], params)

    def test_authorize_id_token(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
            },
        )
        assert "id_token=" in rv.location
        assert "state=bar" in rv.location
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        self.validate_claims(params["id_token"], params)

    def test_response_mode_query(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "response_mode": "query",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
            },
        )
        assert "id_token=" in rv.location
        assert "state=bar" in rv.location
        params = dict(url_decode(urlparse.urlparse(rv.location).query))
        self.validate_claims(params["id_token"], params)

    def test_response_mode_form_post(self):
        self.prepare_data()
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "response_mode": "form_post",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
            },
        )
        assert b'name="id_token"' in rv.data
        assert b'name="state"' in rv.data

    def test_client_metadata_custom_alg(self):
        """If the client metadata 'id_token_signed_response_alg' is defined,
        it should be used to sign id_tokens."""
        self.prepare_data(id_token_signed_response_alg="HS384")
        self.app.config["OAUTH2_JWT_ALG"] = None
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "foo",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
                "nonce": "abc",
            },
        )
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        claims = self.validate_claims(params["id_token"], params, "HS384")
        assert claims.header["alg"] == "HS384"

    def test_client_metadata_alg_none(self):
        """The 'none' 'id_token_signed_response_alg' alg should be
        forbidden in non implicit flows."""
        self.prepare_data(id_token_signed_response_alg="none")
        self.app.config["OAUTH2_JWT_ALG"] = None
        rv = self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token",
                "client_id": "implicit-client",
                "scope": "openid profile",
                "state": "foo",
                "redirect_uri": "https://a.b/c",
                "user_id": "1",
                "nonce": "abc",
            },
        )
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        assert params["error"] == "invalid_request"
