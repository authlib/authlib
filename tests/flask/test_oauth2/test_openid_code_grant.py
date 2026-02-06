import time

import pytest
from flask import current_app
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import url_encode
from authlib.common.urls import urlparse
from authlib.jose import JsonWebToken
from authlib.jose import jwt
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import exists_nonce
from .models import save_authorization_code
from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile address",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def server(server, app):
    app.config.update(
        {
            "OAUTH2_JWT_ISS": "Authlib",
            "OAUTH2_JWT_KEY": "secret",
            "OAUTH2_JWT_ALG": "HS256",
        }
    )
    return server


def register_oidc_code_grant(server, require_nonce=False):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    class OpenIDCode(_OpenIDCode):
        def get_jwt_config(self, grant, client):
            key = current_app.config.get("OAUTH2_JWT_KEY")
            alg = current_app.config.get("OAUTH2_JWT_ALG")
            iss = current_app.config.get("OAUTH2_JWT_ISS")
            return dict(key=key, alg=alg, iss=iss, exp=3600)

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

    server.register_grant(
        AuthorizationCodeGrant, [OpenIDCode(require_nonce=require_nonce)]
    )


def test_authorize_token(test_client, server):
    register_oidc_code_grant(
        server,
    )
    auth_request_time = time.time()
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "state": "bar",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "bar"

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
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


def test_pure_code_flow(test_client, server):
    register_oidc_code_grant(
        server,
    )
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "state": "bar",
            "scope": "profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "bar"

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" not in resp


def test_require_nonce(test_client, server):
    register_oidc_code_grant(server, require_nonce=True)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "user_id": "1",
            "state": "bar",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_request"
    assert params["error_description"] == "Missing 'nonce' in request."


def test_nonce_replay(test_client, server):
    register_oidc_code_grant(
        server,
    )
    data = {
        "response_type": "code",
        "client_id": "client-id",
        "user_id": "1",
        "state": "bar",
        "nonce": "abc",
        "scope": "openid profile",
        "redirect_uri": "https://client.test",
    }
    rv = test_client.post("/oauth/authorize", data=data)
    assert "code=" in rv.location

    rv = test_client.post("/oauth/authorize", data=data)
    assert "error=" in rv.location


def test_prompt(test_client, server):
    register_oidc_code_grant(
        server,
    )
    params = [
        ("response_type", "code"),
        ("client_id", "client-id"),
        ("state", "bar"),
        ("nonce", "abc"),
        ("scope", "openid profile"),
        ("redirect_uri", "https://client.test"),
    ]
    query = url_encode(params)
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"

    query = url_encode(params + [("user_id", "1")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"ok"

    query = url_encode(params + [("prompt", "login")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"

    query = url_encode(params + [("user_id", "1"), ("prompt", "login")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"


def test_prompt_none_not_logged(test_client, server):
    register_oidc_code_grant(
        server,
    )
    params = [
        ("response_type", "code"),
        ("client_id", "client-id"),
        ("state", "bar"),
        ("nonce", "abc"),
        ("scope", "openid profile"),
        ("redirect_uri", "https://client.test"),
        ("prompt", "none"),
    ]
    query = url_encode(params)
    rv = test_client.get("/oauth/authorize?" + query)

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "login_required"
    assert params["state"] == "bar"


def test_client_metadata_custom_alg(test_client, server, client, db, app):
    """If the client metadata 'id_token_signed_response_alg' is defined,
    it should be used to sign id_tokens."""
    register_oidc_code_grant(
        server,
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile address",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "HS384",
        }
    )
    db.session.add(client)
    db.session.commit()
    del app.config["OAUTH2_JWT_ALG"]

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "state": "bar",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    claims = jwt.decode(
        resp["id_token"],
        "secret",
        claims_cls=CodeIDToken,
        claims_options={"iss": {"value": "Authlib"}},
    )
    claims.validate()
    assert claims.header["alg"] == "HS384"


def test_client_metadata_alg_none(test_client, server, app, db, client):
    """The 'none' 'id_token_signed_response_alg' alg should be
    supported in non implicit flows."""
    register_oidc_code_grant(
        server,
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile address",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "none",
        }
    )
    db.session.add(client)
    db.session.commit()

    del app.config["OAUTH2_JWT_ALG"]
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "state": "bar",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    jwt_none = JsonWebToken(["none"])
    claims = jwt_none.decode(
        resp["id_token"],
        "secret",
        claims_cls=CodeIDToken,
        claims_options={"iss": {"value": "Authlib"}},
    )
    claims.validate()
    assert claims.header["alg"] == "none"


@pytest.mark.parametrize(
    "alg, private_key, public_key",
    [
        (
            "RS256",
            read_file_path("jwk_private.json"),
            read_file_path("jwk_public.json"),
        ),
        (
            "PS256",
            read_file_path("jwks_private.json"),
            read_file_path("jwks_public.json"),
        ),
        (
            "ES512",
            read_file_path("secp521r1-private.json"),
            read_file_path("secp521r1-public.json"),
        ),
        (
            "RS256",
            read_file_path("rsa_private.pem"),
            read_file_path("rsa_public.pem"),
        ),
    ],
)
def test_authorize_token_algs(test_client, server, app, alg, private_key, public_key):
    # generate refresh token
    app.config["OAUTH2_JWT_KEY"] = private_key
    app.config["OAUTH2_JWT_ALG"] = alg
    register_oidc_code_grant(
        server,
    )
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "state": "bar",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["state"] == "bar"

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp

    claims = jwt.decode(
        resp["id_token"],
        public_key,
        claims_cls=CodeIDToken,
        claims_options={"iss": {"value": "Authlib"}},
    )
    claims.validate()


def test_deprecated_get_jwt_config_signature(test_client, server, db, user):
    """Using the old get_jwt_config(self, grant) signature should emit a DeprecationWarning."""

    class DeprecatedOpenIDCode(_OpenIDCode):
        def get_jwt_config(self, grant):
            return {"key": "secret", "alg": "HS256", "iss": "Authlib", "exp": 3600}

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant, [DeprecatedOpenIDCode()])

    client = Client(
        user_id=user.id,
        client_id="deprecated-client",
        client_secret="secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "deprecated-client",
            "state": "bar",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    code = params["code"]

    with pytest.warns(DeprecationWarning, match="get_jwt_config.*version 1.8"):
        test_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "https://client.test",
                "code": code,
            },
            headers=create_basic_header("deprecated-client", "secret"),
        )
