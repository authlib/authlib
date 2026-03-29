import pytest
from flask import current_app

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.jose import JsonWebToken
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core.grants import OpenIDImplicitGrant as _OpenIDImplicitGrant

from .models import Client
from .models import exists_nonce

authorize_url = "/oauth/authorize?response_type=token&client_id=client-id"


@pytest.fixture(autouse=True)
def server(server):
    class OpenIDImplicitGrant(_OpenIDImplicitGrant):
        def get_jwt_config(self, client):
            alg = current_app.config.get("OAUTH2_JWT_ALG", "HS256")
            return dict(key="secret", alg=alg, iss="Authlib", exp=3600)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

    server.register_grant(OpenIDImplicitGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["id_token", "id_token token"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def validate_claims(id_token, params, alg="HS256"):
    jwt = JsonWebToken([alg])
    claims = jwt.decode(
        id_token, "secret", claims_cls=ImplicitIDToken, claims_params=params
    )
    claims.validate()
    return claims


def test_consent_view(test_client):
    rv = test_client.get(
        add_params_to_uri(
            "/oauth/authorize",
            {
                "response_type": "id_token",
                "client_id": "client-id",
                "scope": "openid profile",
                "state": "foo",
                "redirect_uri": "https://client.test/callback",
                "user_id": "1",
            },
        )
    )
    assert "error=invalid_request" in rv.location
    assert "nonce" in rv.location


def test_require_nonce(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    assert "error=invalid_request" in rv.location
    assert "nonce" in rv.location


def test_missing_openid_in_scope(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token token",
            "client_id": "client-id",
            "scope": "profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    assert "error=invalid_scope" in rv.location


def test_denied(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
        },
    )
    assert "error=access_denied" in rv.location


def test_authorize_access_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    assert "access_token=" in rv.location
    assert "id_token=" in rv.location
    assert "state=bar" in rv.location
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    validate_claims(params["id_token"], params)


def test_authorize_id_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    assert "id_token=" in rv.location
    assert "state=bar" in rv.location
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    validate_claims(params["id_token"], params)


def test_response_mode_query(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "response_mode": "query",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    assert "id_token=" in rv.location
    assert "state=bar" in rv.location
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    validate_claims(params["id_token"], params)


def test_response_mode_form_post(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "response_mode": "form_post",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    assert b'name="id_token"' in rv.data
    assert b'name="state"' in rv.data


def test_client_metadata_custom_alg(test_client, app, db, client):
    """If the client metadata 'id_token_signed_response_alg' is defined,
    it should be used to sign id_tokens."""
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["id_token", "id_token token"],
            "id_token_signed_response_alg": "HS384",
        }
    )
    db.session.add(client)
    db.session.commit()

    app.config["OAUTH2_JWT_ALG"] = None
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "foo",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
            "nonce": "abc",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    claims = validate_claims(params["id_token"], params, "HS384")
    assert claims.header["alg"] == "HS384"


def test_client_metadata_alg_none(test_client, app, db, client):
    """The 'none' 'id_token_signed_response_alg' alg should be
    forbidden in non implicit flows."""
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["id_token", "id_token token"],
            "id_token_signed_response_alg": "none",
        }
    )
    db.session.add(client)
    db.session.commit()

    app.config["OAUTH2_JWT_ALG"] = None
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "foo",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
            "nonce": "abc",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "invalid_request"


def test_deprecated_get_jwt_config_signature(user):
    """Using the old get_jwt_config(self) signature should emit a DeprecationWarning."""

    class DeprecatedImplicitGrant(_OpenIDImplicitGrant):
        def get_jwt_config(self):
            return {"key": "secret", "alg": "HS256", "iss": "Authlib", "exp": 3600}

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

    client = Client(
        user_id=user.id,
        client_id="deprecated-client",
        client_secret="secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "scope": "openid profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["id_token"],
        }
    )

    request = OAuth2Request("POST", "https://server.test/authorize")
    request.payload = BasicOAuth2Payload({"nonce": "test-nonce"})
    request.client = client
    request.user = user

    grant = DeprecatedImplicitGrant(request, client)
    token = {"scope": "openid", "expires_in": 3600}

    with pytest.warns(DeprecationWarning, match="get_jwt_config.*version 1.8"):
        grant.process_implicit_token(token)
