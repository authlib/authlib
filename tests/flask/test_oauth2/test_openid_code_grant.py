import time
from contextlib import nullcontext

import pytest
from flask import current_app
from flask import json
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.common.urls import url_decode
from authlib.common.urls import url_encode
from authlib.common.urls import urlparse
from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.prompt_create import PromptCreate
from tests.util import HMAC_SECRET
from tests.util import read_file_path

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
            "id_token_signed_response_alg": "HS256",
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
            "OAUTH2_JWT_KEY": OctKey.import_key(HMAC_SECRET),
            "OAUTH2_JWT_ALG": "HS256",
        }
    )
    return server


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class TupleAuthorizationCodeGrant(AuthorizationCodeGrant):
    def create_token_response(self):
        response = super().create_token_response()
        return response.status_code, response.body, response.headers


class OpenIDCode(_OpenIDCode):
    def resolve_client_private_key(self, client):
        return current_app.config["OAUTH2_JWT_KEY"]

    def get_client_claims(self, client):
        return {"iss": current_app.config["OAUTH2_JWT_ISS"]}

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


class LegacyOpenIDCode(_OpenIDCode):
    def get_jwt_config(self, grant, client):
        key = current_app.config.get("OAUTH2_JWT_KEY")
        alg = current_app.config.get("OAUTH2_JWT_ALG")
        iss = current_app.config.get("OAUTH2_JWT_ISS")
        return dict(key=key, alg=alg, iss=iss, exp=3600)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def generate_user_info(self, user, scopes):
        return user.generate_user_info(scopes)


def register_oidc_code_grant(
    server, require_nonce=False, extension=OpenIDCode, grant_cls=AuthorizationCodeGrant
):
    server.register_grant(grant_cls, [extension(require_nonce=require_nonce)])


@pytest.mark.parametrize(
    "grant_cls", [AuthorizationCodeGrant, TupleAuthorizationCodeGrant]
)
def test_authorize_token(test_client, server, grant_cls):
    """The token response contains an ID token, also when the grant returns
    a (status_code, body, headers) tuple."""
    register_oidc_code_grant(server, grant_cls=grant_cls)
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
    deprecated = grant_cls is TupleAuthorizationCodeGrant
    with pytest.warns(AuthlibDeprecationWarning) if deprecated else nullcontext():
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

    token = jwt.decode(resp["id_token"], key=OctKey.import_key(HMAC_SECRET))
    claims = CodeIDToken(
        token.claims,
        token.header,
        {"iss": {"value": "Authlib"}},
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


PROMPT_PARAMS = [
    ("response_type", "code"),
    ("client_id", "client-id"),
    ("state", "bar"),
    ("nonce", "abc"),
    ("scope", "openid profile"),
    ("redirect_uri", "https://client.test"),
]


@pytest.mark.parametrize("user_params", [[], [("user_id", "1")]])
@pytest.mark.parametrize(
    "prompt", ["create", "login create", "consent create", "select_account create"]
)
def test_prompt_create(test_client, server, user_params, prompt):
    """With PromptCreate, the grant prompt is 'create'."""
    register_oidc_code_grant(server)
    server.register_extension(PromptCreate())
    query = url_encode(PROMPT_PARAMS + user_params + [("prompt", prompt)])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"create"


def test_prompt_create_with_none(test_client, server):
    """With PromptCreate, 'none' cannot be combined with 'create'."""
    register_oidc_code_grant(server)
    server.register_extension(PromptCreate())
    query = url_encode(PROMPT_PARAMS + [("user_id", "1"), ("prompt", "none create")])
    rv = test_client.get("/oauth/authorize?" + query)

    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_request"


def test_prompt_multiple_values_prefers_login_without_user(test_client, server):
    """Without a user, 'login consent' gives the 'login' prompt."""
    register_oidc_code_grant(server)
    query = url_encode(PROMPT_PARAMS + [("prompt", "login consent")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"


def test_prompt_create_without_openid_scope(test_client, server):
    """PromptCreate does not change requests without the openid scope."""
    register_oidc_code_grant(server)
    server.register_extension(PromptCreate())
    params = [(k, "profile" if k == "scope" else v) for k, v in PROMPT_PARAMS]
    query = url_encode(params + [("user_id", "1"), ("prompt", "create")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"ok"


def test_prompt_create_without_extension(test_client, server):
    """Without PromptCreate, 'create' does not change the grant prompt."""
    register_oidc_code_grant(server)
    query = url_encode(PROMPT_PARAMS + [("prompt", "create")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"

    query = url_encode(PROMPT_PARAMS + [("user_id", "1"), ("prompt", "create")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"ok"


@pytest.mark.filterwarnings(
    'ignore:JWS algorithm "none" is deprecated:joserfc.errors.SecurityWarning'
)
def test_client_metadata_alg_none(test_client, server, db, client):
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
    token = jwt.decode(
        resp["id_token"],
        key=OctKey.import_key(HMAC_SECRET),
        algorithms=["none"],
    )
    claims = CodeIDToken(
        token.claims,
        token.header,
        {"iss": {"value": "Authlib"}},
    )
    claims.validate()
    assert claims.header["alg"] == "none"


@pytest.mark.parametrize(
    "alg, private_key, public_key",
    [
        (
            "RS256",
            RSAKey.import_key(read_file_path("jwk_private.json")),
            RSAKey.import_key(read_file_path("jwk_public.json")),
        ),
        (
            "PS256",
            KeySet.import_key_set(read_file_path("jwks_private.json")),
            KeySet.import_key_set(read_file_path("jwks_public.json")),
        ),
        (
            "ES512",
            ECKey.import_key(read_file_path("secp521r1-private.json")),
            ECKey.import_key(read_file_path("secp521r1-public.json")),
        ),
        (
            "RS256",
            RSAKey.import_key(read_file_path("rsa_private.pem")),
            RSAKey.import_key(read_file_path("rsa_public.pem")),
        ),
    ],
)
def test_authorize_token_algs(
    test_client, server, app, db, client, alg, private_key, public_key
):
    app.config["OAUTH2_JWT_KEY"] = private_key
    client.set_client_metadata(
        {**client.client_metadata, "id_token_signed_response_alg": alg}
    )
    db.session.commit()
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

    token = jwt.decode(
        resp["id_token"],
        key=public_key,
        algorithms=[alg],
    )
    claims = CodeIDToken(
        token.claims,
        token.header,
        {"iss": {"value": "Authlib"}},
    )
    claims.validate()


def test_default_alg_rs256(test_client, server, app, db, client):
    """Without 'id_token_signed_response_alg', the id_token is signed with RS256."""
    app.config["OAUTH2_JWT_KEY"] = RSAKey.import_key(read_file_path("jwk_private.json"))
    metadata = dict(client.client_metadata)
    del metadata["id_token_signed_response_alg"]
    client.set_client_metadata(metadata)
    db.session.commit()
    register_oidc_code_grant(server)

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
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": params["code"],
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    resp = json.loads(rv.data)
    token = jwt.decode(
        resp["id_token"],
        key=RSAKey.import_key(read_file_path("jwk_public.json")),
        algorithms=["RS256"],
    )
    assert token.header["alg"] == "RS256"
