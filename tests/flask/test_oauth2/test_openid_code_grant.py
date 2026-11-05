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
from authlib.oauth2.rfc9470 import StepUpAuthentication
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.prompt_create import PromptValues
from tests.util import HMAC_SECRET
from tests.util import read_file_path

from .models import AuthorizationSession
from .models import CodeGrantMixin
from .models import exists_nonce
from .models import save_authorization_code
from .oauth2_server import SupportedPromptValues
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


def unknown_auth_time(monkeypatch):
    """Make the login time of the authorization sessions unknown."""
    monkeypatch.setattr(
        AuthorizationSession,
        "get_interaction_time",
        lambda self, request, interaction: None,
    )


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


def exchange_code_for_id_token(test_client, extra=None):
    """Authorize, exchange the code, and return the ID token claims."""
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
            **(extra or {}),
        },
    )
    code = dict(url_decode(urlparse.urlparse(rv.location).query))["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    id_token = json.loads(rv.data)["id_token"]
    return jwt.decode(id_token, key=OctKey.import_key(HMAC_SECRET)).claims


def test_auth_time_claim(test_client, server):
    """The auth_time claim of the ID token is the time of the user
    authentication, not the time the code was created."""
    register_oidc_code_grant(server)
    claims = exchange_code_for_id_token(test_client, {"auth_time": "1000000000"})
    assert claims["auth_time"] == 1000000000


def test_unknown_auth_time_claim(test_client, server, monkeypatch):
    """When the login time is unknown, the ID token has no auth_time."""
    unknown_auth_time(monkeypatch)
    register_oidc_code_grant(server)
    claims = exchange_code_for_id_token(test_client)
    assert "auth_time" not in claims


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


def test_multiple_nonce(test_client, server):
    """A repeated nonce gives an invalid_request error."""
    register_oidc_code_grant(server)
    rv = test_client.get(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&scope=openid+profile&nonce=abc&nonce=def"
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
    assert resp["error_description"] == "Multiple 'nonce' in request."


def test_repeated_openid_parameter_without_openid_scope(test_client, server):
    """Without the openid scope, the OpenID Connect parameters can be
    repeated."""
    register_oidc_code_grant(server)
    rv = test_client.get(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&scope=profile&prompt=login&prompt=consent"
    )
    assert rv.data == b"login"


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


@pytest.mark.parametrize(
    "prompt", ["create", "login create", "consent create", "select_account create"]
)
def test_prompt_create(test_client, server, prompt):
    """With PromptValues, the grant prompt is 'create' for an anonymous
    user."""
    register_oidc_code_grant(server)
    server.register_extension(SupportedPromptValues())
    query = url_encode(PROMPT_PARAMS + [("prompt", prompt)])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"create"


@pytest.mark.parametrize(
    "prompt,expected",
    [
        ("create", b"ok"),
        ("consent create", b"consent"),
        ("select_account create", b"select_account"),
        ("login create", b"login"),
    ],
)
def test_prompt_create_with_logged_user(test_client, server, prompt, expected):
    """For a logged-in user, PromptValues does not change the
    interactions."""
    register_oidc_code_grant(server)
    server.register_extension(SupportedPromptValues())
    query = url_encode(PROMPT_PARAMS + [("user_id", "1"), ("prompt", prompt)])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == expected


class LimitedPromptValues(PromptValues):
    """PromptValues with a short list of supported values."""

    def get_server_metadata(self):
        return {"prompt_values_supported": ["login", "create"]}


@pytest.mark.parametrize("prompt", ["consent", "login consent", "none", "foo"])
def test_prompt_create_unsupported_value(test_client, server, prompt):
    """A prompt value that is not in prompt_values_supported gives an HTTP
    400 invalid_request error, without redirection."""
    register_oidc_code_grant(server)
    server.register_extension(LimitedPromptValues())
    query = url_encode(PROMPT_PARAMS + [("prompt", prompt)])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.status_code == 400
    assert rv.location is None
    assert rv.json["error"] == "invalid_request"
    assert "prompt" in rv.json["error_description"]


@pytest.mark.parametrize(
    "name,value,error",
    [
        ("client_id", "unknown", "invalid_client"),
        ("redirect_uri", "https://unknown.test", "invalid_request"),
    ],
)
def test_prompt_create_unsupported_value_after_client(
    test_client, server, name, value, error
):
    """The client and the redirect URI are checked before the prompt
    values."""
    register_oidc_code_grant(server)
    server.register_extension(LimitedPromptValues())
    params = [(k, value if k == name else v) for k, v in PROMPT_PARAMS]
    rv = test_client.get("/oauth/authorize?" + url_encode([*params, ("prompt", "foo")]))
    assert rv.status_code == 400
    assert rv.json["error"] == error
    assert "prompt" not in rv.json.get("error_description", "")


@pytest.mark.parametrize(
    "extension,scope,prompt,expected",
    [
        (LimitedPromptValues, "openid profile", "login", b"login"),
        (PromptValues, "openid profile", "consent", b"login"),
        (LimitedPromptValues, "profile", "consent", b"login"),
    ],
)
def test_prompt_create_supported_value(
    test_client, server, extension, scope, prompt, expected
):
    """The prompt values are accepted when they are supported, when the
    server metadata has no prompt_values_supported, or without the openid
    scope."""
    register_oidc_code_grant(server)
    server.register_extension(extension())
    params = [(k, scope if k == "scope" else v) for k, v in PROMPT_PARAMS]
    rv = test_client.get(
        "/oauth/authorize?" + url_encode([*params, ("prompt", prompt)])
    )
    assert rv.data == expected


def test_prompt_create_not_supported(test_client, server):
    """When prompt_values_supported does not contain 'create', prompt=create
    gives an HTTP 400 invalid_request error."""

    class NoCreatePromptValues(PromptValues):
        def get_server_metadata(self):
            return {"prompt_values_supported": ["none", "login"]}

    register_oidc_code_grant(server)
    server.register_extension(NoCreatePromptValues())
    rv = test_client.get(
        "/oauth/authorize?" + url_encode([*PROMPT_PARAMS, ("prompt", "create")])
    )
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"


def test_prompt_create_does_not_skip_max_age(test_client, server):
    """When a logged-in user must log in again because of max_age, the grant
    prompt stays 'login'."""
    register_oidc_code_grant(server)
    server.register_extension(SupportedPromptValues())
    rv = authorize_max_age(test_client, 60, int(time.time()) - 7200, "create")
    assert rv.data == b"login"


def test_prompt_create_with_none(test_client, server):
    """With PromptValues, 'none' cannot be combined with 'create'."""
    register_oidc_code_grant(server)
    server.register_extension(SupportedPromptValues())
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
    """PromptValues does not change requests without the openid scope."""
    register_oidc_code_grant(server)
    server.register_extension(SupportedPromptValues())
    params = [(k, "profile" if k == "scope" else v) for k, v in PROMPT_PARAMS]
    query = url_encode(params + [("user_id", "1"), ("prompt", "create")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"ok"


@pytest.mark.parametrize("extension_cls", [None, PromptValues])
def test_prompt_create_without_extension(test_client, server, extension_cls):
    """Without the extension, or without prompt_values_supported, 'create'
    does not change the grant prompt."""
    register_oidc_code_grant(server)
    if extension_cls:
        server.register_extension(extension_cls())

    query = url_encode(PROMPT_PARAMS + [("prompt", "create")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"

    query = url_encode(PROMPT_PARAMS + [("user_id", "1"), ("prompt", "create")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"ok"


def authorize_max_age(test_client, max_age, auth_time, prompt=None):
    """Send an authorization request with a logged user and a max_age."""
    params = PROMPT_PARAMS + [("user_id", "1"), ("auth_time", str(auth_time))]
    if max_age is not None:
        params.append(("max_age", str(max_age)))

    if prompt:
        params.append(("prompt", prompt))

    return test_client.get("/oauth/authorize?" + url_encode(params))


def test_max_age_recent_authentication(test_client, server):
    """An authentication younger than max_age needs no login."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 3600, int(time.time()) - 60)
    assert rv.data == b"ok"


def test_max_age_old_authentication(test_client, server):
    """An authentication older than max_age asks for a login."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 3600, int(time.time()) - 7200)
    assert rv.data == b"login"


def test_max_age_old_authentication_prompt_none(test_client, server):
    """With prompt=none, an authentication older than max_age gives
    login_required."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 3600, int(time.time()) - 7200, "none")
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "login_required"
    assert params["state"] == "bar"


def test_max_age_old_authentication_prompt_consent(test_client, server):
    """The login comes before the consent."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 3600, int(time.time()) - 7200, "consent")
    assert rv.data == b"login"


def test_max_age_zero(test_client, server):
    """max_age=0 is equivalent to prompt=login."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 0, int(time.time()))
    assert rv.data == b"login"


@pytest.mark.parametrize("max_age", ["-1", "1.5", "abc", "١٢", "9" * 5000])
def test_max_age_invalid(test_client, server, max_age):
    """A max_age that is not a non-negative integer gives invalid_request."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, max_age, int(time.time()))
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "invalid_request"
    assert params["state"] == "bar"


def test_max_age_empty(test_client, server):
    """An empty max_age is ignored."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, "", int(time.time()) - 7200)
    assert rv.data == b"ok"


def test_default_max_age(test_client, server, db, client):
    """The default_max_age client metadata applies without max_age."""
    register_oidc_code_grant(server)
    client.set_client_metadata({**client.client_metadata, "default_max_age": 3600})
    db.session.add(client)
    db.session.commit()

    rv = authorize_max_age(test_client, None, int(time.time()) - 7200)
    assert rv.data == b"login"

    rv = authorize_max_age(test_client, None, int(time.time()) - 60)
    assert rv.data == b"ok"


def test_invalid_default_max_age(test_client, server, db, client):
    """An invalid default_max_age client metadata is ignored."""
    register_oidc_code_grant(server)
    client.set_client_metadata({**client.client_metadata, "default_max_age": -1})
    db.session.add(client)
    db.session.commit()

    rv = authorize_max_age(test_client, None, int(time.time()) - 7200)
    assert rv.data == b"ok"


def test_max_age_overrides_default_max_age(test_client, server, db, client):
    """The max_age parameter overrides the default_max_age client metadata."""
    register_oidc_code_grant(server)
    client.set_client_metadata({**client.client_metadata, "default_max_age": 60})
    db.session.add(client)
    db.session.commit()

    rv = authorize_max_age(test_client, 3600, int(time.time()) - 600)
    assert rv.data == b"ok"


def test_max_age_unknown_auth_time(test_client, server, monkeypatch):
    """When the login time is unknown, max_age asks for a login."""
    unknown_auth_time(monkeypatch)
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 3600, int(time.time()))
    assert rv.data == b"login"

    rv = authorize_max_age(test_client, None, int(time.time()))
    assert rv.data == b"ok"


@pytest.mark.parametrize("authorization_session", [None], indirect=True)
def test_without_authorization_session(test_client, server, authorization_session):
    """Without an authorization session, max_age is not enforced, except
    max_age=0, and a deprecation warning is shown."""
    register_oidc_code_grant(server)
    with pytest.warns(AuthlibDeprecationWarning, match="authorization session"):
        rv = authorize_max_age(test_client, 3600, int(time.time()) - 7200)

    assert rv.data == b"ok"

    rv = authorize_max_age(test_client, 0, int(time.time()))
    assert rv.data == b"login"


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


@pytest.mark.parametrize("authorization_session", [None], indirect=True)
def test_without_authorization_session_keeps_auth_time(
    test_client, server, authorization_session
):
    """Without an authorization session, the ID token auth_time is the
    current time."""
    register_oidc_code_grant(server)
    before = int(time.time())
    with pytest.warns(AuthlibDeprecationWarning, match="authorization session"):
        claims = exchange_code_for_id_token(test_client, {"max_age": "3600"})

    assert claims["auth_time"] >= before


def test_denied_does_not_read_auth_time(test_client, server, monkeypatch):
    """The login time is not read when the user denies the request."""

    def get_interaction_time(self, request, interaction):
        raise AssertionError("the login time should not be read")

    monkeypatch.setattr(
        AuthorizationSession, "get_interaction_time", get_interaction_time
    )
    register_oidc_code_grant(server)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "access_denied"


@pytest.mark.parametrize("params", [{"prompt": "login"}, {"max_age": 0}])
def test_login_after_request_start(test_client, server, params, request_time):
    """With get_request_time, a login after the start of the request
    satisfies prompt=login and max_age=0."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(
        test_client, params.get("max_age"), int(time.time()) - 60, params.get("prompt")
    )
    assert rv.data == b"login"

    rv = authorize_max_age(
        test_client, params.get("max_age"), int(time.time()), params.get("prompt")
    )
    assert rv.data == b"ok"


def shift_request_times(test_client, seconds):
    """Move the start of the stored authorization requests back in time."""
    with test_client.session_transaction() as session:
        session["authlib_request_times"] = {
            key: value - seconds
            for key, value in session["authlib_request_times"].items()
        }


def test_login_for_another_request(test_client, server, request_time):
    """A login for one authorization request does not satisfy prompt=login in
    another one."""
    register_oidc_code_grant(server)
    auth_time = int(time.time()) - 60
    rv = authorize_max_age(test_client, None, auth_time, "login")
    assert rv.data == b"login"

    shift_request_times(test_client, 120)
    rv = authorize_max_age(test_client, None, auth_time, "login")
    assert rv.data == b"ok"

    params = [(k, "baz" if k == "state" else v) for k, v in PROMPT_PARAMS]
    query = url_encode(
        [*params, ("user_id", "1"), ("auth_time", str(auth_time)), ("prompt", "login")]
    )
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"


def test_max_age_from_request_start(test_client, server, request_time):
    """max_age is measured from the start of the request, so a user can stay
    on the consent page longer than max_age."""
    register_oidc_code_grant(server)
    rv = authorize_max_age(test_client, 60, int(time.time()) - 30)
    assert rv.data == b"ok"

    shift_request_times(test_client, 100)
    rv = authorize_max_age(test_client, 60, int(time.time()) - 130)
    assert rv.data == b"ok"

    rv = authorize_max_age(test_client, 60, int(time.time()) - 170)
    assert rv.data == b"login"


def test_login_after_anonymous_request_start(test_client, server, request_time):
    """The start of the request is kept when the user is not logged in yet, so
    one login is enough."""
    register_oidc_code_grant(server)
    rv = test_client.get(
        "/oauth/authorize?" + url_encode([*PROMPT_PARAMS, ("prompt", "login")])
    )
    assert rv.data == b"login"

    shift_request_times(test_client, 60)
    rv = authorize_max_age(test_client, None, int(time.time()) - 30, "login")
    assert rv.data == b"ok"


def test_account_selection_by_anonymous_login(test_client, server, request_time):
    """The start of the request is kept from the first visit of an anonymous
    user, and their login satisfies prompt=select_account."""
    register_oidc_code_grant(server)
    rv = test_client.get(
        "/oauth/authorize?" + url_encode([*PROMPT_PARAMS, ("prompt", "select_account")])
    )
    assert rv.data == b"login"

    shift_request_times(test_client, 60)
    rv = authorize_max_age(test_client, None, int(time.time()) - 30, "select_account")
    assert rv.data == b"ok"


def test_prompt_none_with_custom_consent_validation(test_client, server):
    """With prompt=none, login_required is redirected to the client, also
    when the grant validates the consent request without calling super()."""

    class CustomGrant(AuthorizationCodeGrant):
        def validate_consent_request(self):
            return self.validate_authorization_request()

    register_oidc_code_grant(server, grant_cls=CustomGrant)
    query = url_encode(PROMPT_PARAMS + [("prompt", "none")])
    rv = test_client.get("/oauth/authorize?" + query)
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "login_required"


def test_error_of_anonymous_user(test_client, server):
    """Per RFC 9700 §4.11.2, the error of an anonymous user waits for the
    login, except with prompt=none. An invalid prompt is not silent."""
    register_oidc_code_grant(server)
    server.scopes_supported = ["openid", "profile"]
    params = [(k, v) for k, v in PROMPT_PARAMS if k != "scope"]
    params.append(("scope", "openid invalid"))
    rv = test_client.get("/oauth/authorize?" + url_encode(params))
    assert rv.data == b"login"

    rv = test_client.get(
        "/oauth/authorize?" + url_encode(params + [("prompt", "none")])
    )
    query = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert query["error"] == "invalid_scope"
    assert query["state"] == "bar"

    rv = test_client.get(
        "/oauth/authorize?" + url_encode(params + [("prompt", "none login")])
    )
    assert rv.data == b"login"


@pytest.mark.parametrize(
    "method,interaction,error",
    [
        ("is_consent_needed", b"consent", "consent_required"),
        (
            "is_account_selection_needed",
            b"select_account",
            "account_selection_required",
        ),
    ],
)
def test_interaction_needed(
    test_client, server, monkeypatch, method, interaction, error
):
    """When the authorization session needs the consent or the account
    selection of the user, it is an interaction. With prompt=none, the server
    returns an error instead."""
    monkeypatch.setattr(AuthorizationSession, method, lambda self, request: True)
    register_oidc_code_grant(server)
    query = url_encode(PROMPT_PARAMS + [("user_id", "1")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == interaction

    auth_time = str(int(time.time()) - 60)
    params = [("user_id", "1"), ("auth_time", auth_time), ("prompt", "none")]
    rv = test_client.get("/oauth/authorize?" + url_encode(PROMPT_PARAMS + params))
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == error
    assert params["state"] == "bar"


def test_consent_after_request_start(test_client, server, monkeypatch, request_time):
    """prompt=consent is satisfied by a consent given after the start of the
    request."""
    consent_time = {"value": int(time.time()) - 60}
    monkeypatch.setattr(
        AuthorizationSession,
        "get_interaction_time",
        lambda self, request, interaction: (
            consent_time["value"] if interaction == "consent" else int(time.time())
        ),
    )
    register_oidc_code_grant(server)
    query = url_encode(PROMPT_PARAMS + [("user_id", "1"), ("prompt", "consent")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"consent"

    consent_time["value"] = int(time.time())
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"ok"


@pytest.mark.parametrize("prompt_create_first", [True, False])
def test_prompt_create_with_max_age(test_client, server, prompt_create_first):
    """For an anonymous user, create comes before login, whatever the order
    of the extensions."""
    register_oidc_code_grant(server)
    extensions = [SupportedPromptValues(), StepUpAuthentication()]
    if not prompt_create_first:
        extensions.reverse()

    for extension in extensions:
        server.register_extension(extension)

    query = url_encode(PROMPT_PARAMS + [("prompt", "create"), ("max_age", "60")])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"create"


@pytest.mark.parametrize(
    "params,read",
    [
        ([], True),
        ([("user_id", "1")], False),
        ([("prompt", "none")], False),
        ([("prompt", "none"), ("max_age", "60")], False),
        ([("prompt", "login")], True),
        ([("prompt", "consent")], True),
        ([("prompt", "select_account")], True),
        ([("max_age", "60")], True),
        ([("user_id", "1"), ("prompt", "login")], True),
        ([("user_id", "1"), ("max_age", "60")], True),
        ([("user_id", "1"), ("prompt", "none"), ("max_age", "60")], False),
    ],
)
def test_request_time_read_when_needed(test_client, server, monkeypatch, params, read):
    """The start time of the request is read on the first visit of an
    anonymous user, and when a rule needs it. It is not read with
    prompt=none."""
    calls = []
    monkeypatch.setattr(
        AuthorizationSession,
        "get_request_time",
        lambda self, request: calls.append(request.authorization_key),
    )
    register_oidc_code_grant(server)
    test_client.get("/oauth/authorize?" + url_encode(PROMPT_PARAMS + params))
    assert bool(calls) == read


def test_request_time_read_for_account_selection(test_client, server, monkeypatch):
    """The start time of the request is read when the account selection is
    needed."""
    calls = []
    monkeypatch.setattr(
        AuthorizationSession,
        "get_request_time",
        lambda self, request: calls.append(request.authorization_key),
    )
    monkeypatch.setattr(
        AuthorizationSession, "is_account_selection_needed", lambda self, r: True
    )
    register_oidc_code_grant(server)
    rv = test_client.get(
        "/oauth/authorize?" + url_encode(PROMPT_PARAMS + [("user_id", "1")])
    )
    assert rv.data == b"select_account"
    assert calls


def test_request_time_not_read_by_step_up_with_prompt_none(
    test_client, server, monkeypatch
):
    """With prompt=none, StepUpAuthentication does not read the start time of
    the request either."""
    calls = []
    monkeypatch.setattr(
        AuthorizationSession,
        "get_request_time",
        lambda self, request: calls.append(request.authorization_key),
    )
    register_oidc_code_grant(server)
    server.register_extension(StepUpAuthentication())
    params = [("user_id", "1"), ("prompt", "none"), ("max_age", "3600")]
    rv = test_client.get("/oauth/authorize?" + url_encode(PROMPT_PARAMS + params))
    assert rv.data == b"ok"
    assert calls == []


def test_request_time_not_read_with_prompt_none_by_earlier_extension(
    test_client, server, monkeypatch
):
    """With prompt=none, the start time is not read, also by an extension
    registered before OpenIDCode."""
    calls = []
    monkeypatch.setattr(
        AuthorizationSession,
        "get_request_time",
        lambda self, request: calls.append(request.authorization_key),
    )

    class ReadRequestTime:
        def __call__(self, grant):
            grant.register_hook(
                lambda grant, redirect_uri: grant.request.request_time,
                after=grant.validate_consent_request,
            )

    server.register_grant(
        AuthorizationCodeGrant, [ReadRequestTime(), OpenIDCode(require_nonce=False)]
    )
    params = [("user_id", "1"), ("prompt", "none")]
    rv = test_client.get("/oauth/authorize?" + url_encode(PROMPT_PARAMS + params))
    assert rv.data == b"ok"
    assert calls == []
