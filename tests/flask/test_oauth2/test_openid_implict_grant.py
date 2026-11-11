import time
from contextlib import nullcontext

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core.grants import OpenIDImplicitGrant as _OpenIDImplicitGrant
from tests.util import HMAC_SECRET
from tests.util import parse_form

from .models import AuthorizationSession
from .models import exists_nonce
from .oauth2_server import SupportedPromptValues
from .oauth2_server import register_form_post

authorize_url = "/oauth/authorize?response_type=token&client_id=client-id"


def deprecated_response_mode():
    """Using response_mode without MultipleResponseTypes is deprecated."""
    return pytest.warns(AuthlibDeprecationWarning, match="MultipleResponseTypes")


@pytest.fixture(autouse=True)
def server(server):
    class OpenIDImplicitGrant(_OpenIDImplicitGrant):
        def resolve_client_private_key(self, client):
            return OctKey.import_key(HMAC_SECRET)

        def get_client_claims(self, client):
            return {"iss": "Authlib", "aud": [client.get_client_id()]}

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
            "id_token_signed_response_alg": "HS256",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def validate_claims(id_token, params, alg="HS256"):
    token = jwt.decode(id_token, OctKey.import_key(HMAC_SECRET), algorithms=[alg])
    claims = ImplicitIDToken(token.claims, token.header, params=params)
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


def test_prompt_create(test_client, server):
    """PromptValues sets the grant prompt to 'create' in the implicit flow."""
    server.register_extension(SupportedPromptValues())
    rv = test_client.get(
        add_params_to_uri(
            "/oauth/authorize",
            {
                "response_type": "id_token",
                "client_id": "client-id",
                "scope": "openid profile",
                "state": "foo",
                "nonce": "abc",
                "redirect_uri": "https://client.test/callback",
                "prompt": "create",
            },
        )
    )
    assert rv.data == b"create"


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


def test_multiple_nonce(test_client):
    """A repeated nonce gives an invalid_request error."""
    rv = test_client.get(
        "/oauth/authorize?response_type=id_token&client_id=client-id"
        "&scope=openid+profile&nonce=abc&nonce=def"
    )
    assert rv.json["error"] == "invalid_request"
    assert rv.json["error_description"] == "Multiple 'nonce' in request."


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


@pytest.mark.parametrize("response_type", ["id_token", "id_token token"])
def test_reject_openid_scope_not_allowed_for_client(
    test_client, client, db, response_type
):
    client.set_client_metadata({**client.client_metadata, "scope": "profile"})
    db.session.commit()

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": response_type,
            "client_id": "client-id",
            "scope": "openid profile",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "invalid_scope"
    assert "id_token" not in params
    assert "access_token" not in params


@pytest.mark.parametrize("response_type", ["id_token", "id_token token"])
def test_custom_token_generator_receives_allowed_scope(
    test_client, server, response_type
):
    def generate_token(client, grant_type, user, scope, **kwargs):
        return {
            "access_token": "custom-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        }

    server.register_token_generator("implicit", generate_token)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": response_type,
            "client_id": "client-id",
            "scope": "openid profile email",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["scope"] == "openid profile"
    assert "id_token" in params


def test_missing_openid_in_scope_does_not_redirect_to_unregistered_uri(test_client):
    """An unregistered redirect_uri must not be followed even when openid scope is missing."""
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token token",
            "client_id": "client-id",
            "scope": "profile",
            "state": "s",
            "nonce": "n",
            "redirect_uri": "https://evil.example.com/phish",
        },
    )
    assert rv.status_code == 400
    assert rv.headers.get("Location") is None


class UntrustedAuthorizationSession(AuthorizationSession):
    def can_redirect_error(self, request, error):
        return False


@pytest.mark.parametrize(
    "authorization_session", [UntrustedAuthorizationSession], indirect=True
)
def test_denied_untrusted_redirect_uri(test_client, authorization_session):
    """When the authorization session does not trust the redirect URI, the
    denial is returned without redirection."""
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
    assert rv.status_code == 400
    assert rv.json["error"] == "access_denied"


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
    assert "state=bar" in rv.location


@pytest.mark.parametrize("response_type", ["id_token token", "token id_token"])
@pytest.mark.parametrize("registered", ["id_token token", "token id_token"])
def test_authorize_access_token(test_client, db, client, response_type, registered):
    """The order of the response_type values does not matter, in the request
    and in the client metadata."""
    client.set_client_metadata(
        {**client.client_metadata, "response_types": ["id_token", registered]}
    )
    db.session.add(client)
    db.session.commit()
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": response_type,
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


@pytest.mark.parametrize("user_id", ["1", ""])
def test_hook_changes_the_response(test_client, server, user_id):
    """A hook on encode_authorization_response adds parameters to the
    fragment, granted or denied."""

    def add_param(server, response):
        response.params.append(("extra", "value"))

    server.register_hook(
        add_param, before=AuthorizationServer.encode_authorization_response
    )
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": user_id,
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["extra"] == "value"
    assert params["state"] == "bar"


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


@pytest.mark.parametrize("registered", [True, False])
@pytest.mark.parametrize("response_mode", ["query", "unknown"])
@pytest.mark.parametrize("user_id", ["1", None])
def test_response_mode_unsupported(
    test_client, server, response_mode, user_id, registered
):
    """The query response mode and unknown response modes are refused.

    The error is returned in the fragment. Before the login, it is returned
    without redirection.
    """
    data = {
        "response_type": "id_token",
        "response_mode": response_mode,
        "client_id": "client-id",
        "scope": "openid profile",
        "state": "bar",
        "nonce": "abc",
        "redirect_uri": "https://client.test/callback",
    }
    if user_id:
        data["user_id"] = user_id

    if registered:
        server.register_extension(MultipleResponseTypes())

    with nullcontext() if registered else deprecated_response_mode():
        rv = test_client.post("/oauth/authorize", data=data)

    if not user_id:
        assert rv.status_code == 400
        assert rv.json["error"] == "invalid_request"
        return

    assert rv.status_code == 303
    location = urlparse.urlparse(rv.location)
    assert not location.query
    params = dict(url_decode(location.fragment))
    assert params["error"] == "invalid_request"
    assert params["state"] == "bar"
    assert "id_token" not in params


def test_response_mode_with_extension(test_client, server):
    """With the MultipleResponseTypes extension, the requested response mode
    is used without deprecation."""
    server.register_extension(MultipleResponseTypes())
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "id_token",
            "response_mode": "fragment",
            "client_id": "client-id",
            "scope": "openid profile",
            "state": "bar",
            "nonce": "abc",
            "redirect_uri": "https://client.test/callback",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"
    validate_claims(params["id_token"], params)


def test_response_mode_deprecated_once(test_client):
    """The deprecation is emitted once per authorization server."""
    data = {
        "response_type": "id_token",
        "response_mode": "fragment",
        "client_id": "client-id",
        "scope": "openid profile",
        "nonce": "abc",
        "redirect_uri": "https://client.test/callback",
        "user_id": "1",
    }
    with deprecated_response_mode() as record:
        test_client.post("/oauth/authorize", data=data)
        test_client.post("/oauth/authorize", data={**data, "nonce": "def"})

    assert len(record) == 1


@pytest.mark.parametrize("registered", [True, False])
def test_response_mode_form_post(test_client, server, registered):
    if registered:
        register_form_post(server)

    with nullcontext() if registered else deprecated_response_mode():
        rv = test_client.post(
            "/oauth/authorize",
            data={
                "response_type": "id_token token",
                "response_mode": "form_post",
                "client_id": "client-id",
                "scope": "openid profile",
                "state": "bar",
                "nonce": "abc",
                "redirect_uri": "https://client.test/callback",
                "user_id": "1",
            },
        )

    assert rv.status_code == 200
    assert rv.headers["Cache-Control"] == "no-store"
    assert rv.headers["Pragma"] == "no-cache"
    form = parse_form(rv.data)
    assert form.action == "https://client.test/callback"
    assert form.values["state"] == "bar"
    assert "access_token" in form.values
    validate_claims(form.values["id_token"], form.values)


@pytest.mark.parametrize("user_id", ["1", None])
@pytest.mark.parametrize("registered", [True, False])
def test_response_mode_form_post_values(test_client, server, user_id, registered):
    """The client receives the form_post values unchanged. Without the
    extension, a denial is sent in the fragment, like the other errors."""
    if registered:
        register_form_post(server)

    state = "a b&c\"<>%'"
    data = {
        "response_type": "id_token",
        "response_mode": "form_post",
        "client_id": "client-id",
        "scope": "openid profile",
        "state": state,
        "nonce": "abc",
        "redirect_uri": "https://client.test/callback",
    }
    if user_id:
        data["user_id"] = user_id

    with nullcontext() if registered else deprecated_response_mode():
        rv = test_client.post("/oauth/authorize", data=data)

    if not registered and not user_id:
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        assert params["error"] == "access_denied"
        assert params["state"] == state
        return

    form = parse_form(rv.data)
    assert form.values["state"] == state
    if not user_id:
        assert form.values["error_description"] == (
            "The resource owner or authorization server denied the request"
        )


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "javascript://client.test/%0Aalert(1)",
        "JavaScript://client.test/\nalert(1)",
        "com.example.app://client.test/callback",
    ],
)
@pytest.mark.parametrize("user_id", ["1", None])
@pytest.mark.parametrize("default_response_mode", [False, True])
@pytest.mark.parametrize("registered", [False, True])
def test_response_mode_form_post_non_http_redirect_uri(
    test_client,
    server,
    db,
    client,
    monkeypatch,
    redirect_uri,
    user_id,
    default_response_mode,
    registered,
):
    """A form_post response must not target a non-HTTP redirect URI.

    The request is refused before any form is rendered, whether the user
    approves or denies the authorization.
    """
    client.set_client_metadata(
        {
            "redirect_uris": [redirect_uri],
            "scope": "openid profile",
            "token_endpoint_auth_method": "none",
            "response_types": ["id_token", "id_token token"],
            "id_token_signed_response_alg": "HS256",
        }
    )
    db.session.add(client)
    db.session.commit()

    data = {
        "response_type": "id_token",
        "response_mode": "form_post",
        "client_id": "client-id",
        "scope": "openid profile",
        "state": "bar",
        "nonce": "abc",
        "redirect_uri": redirect_uri,
    }
    if user_id:
        data["user_id"] = user_id
    if default_response_mode:
        monkeypatch.setattr(_OpenIDImplicitGrant, "RESPONSE_MODE", "form_post")
        del data["response_mode"]

    if registered:
        register_form_post(server)

    with (
        nullcontext()
        if default_response_mode or registered
        else deprecated_response_mode()
    ):
        rv = test_client.post("/oauth/authorize", data=data)

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert rv.location is None
    assert b"<form" not in rv.data


def test_client_metadata_custom_alg(test_client, db, client):
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


def test_client_metadata_alg_none(test_client, db, client):
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


def test_default_response_mode_is_deprecated():
    """DEFAULT_RESPONSE_MODE still sets the response mode, with a deprecation."""
    with pytest.warns(AuthlibDeprecationWarning, match="DEFAULT_RESPONSE_MODE"):

        class FormPostGrant(_OpenIDImplicitGrant):
            DEFAULT_RESPONSE_MODE = "form_post"

    assert FormPostGrant.RESPONSE_MODE == "form_post"


IMPLICIT_PARAMS = {
    "response_type": "id_token",
    "client_id": "client-id",
    "scope": "openid profile",
    "state": "bar",
    "nonce": "abc",
    "redirect_uri": "https://client.test/callback",
    "user_id": "1",
}


def test_auth_time_claim(test_client):
    """The auth_time claim of the ID token comes from get_auth_time."""
    rv = test_client.post(
        "/oauth/authorize", data={**IMPLICIT_PARAMS, "auth_time": "1000000000"}
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    claims = validate_claims(params["id_token"], params)
    assert claims["auth_time"] == 1000000000


def test_auth_time_claim_is_an_integer(test_client, monkeypatch):
    """A float login time becomes an integer auth_time."""
    monkeypatch.setattr(
        AuthorizationSession,
        "get_interaction_time",
        lambda self, request, interaction: 1000000000.75,
    )
    rv = test_client.post("/oauth/authorize", data=IMPLICIT_PARAMS)
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    claims = validate_claims(params["id_token"], params)
    assert claims["auth_time"] == 1000000000
    assert isinstance(claims["auth_time"], int)


def test_unknown_auth_time_claim(test_client, monkeypatch):
    """When the login time is unknown, the ID token has no auth_time."""
    monkeypatch.setattr(
        AuthorizationSession,
        "get_interaction_time",
        lambda self, request, interaction: None,
    )
    rv = test_client.post("/oauth/authorize", data=IMPLICIT_PARAMS)
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    claims = validate_claims(params["id_token"], params)
    assert "auth_time" not in claims


def test_max_age_old_authentication(test_client):
    """An authentication older than max_age asks for a login."""
    auth_time = str(int(time.time()) - 7200)
    query = {**IMPLICIT_PARAMS, "max_age": "3600", "auth_time": auth_time}
    rv = test_client.get(add_params_to_uri("/oauth/authorize", query))
    assert rv.data == b"login"

    query["auth_time"] = str(int(time.time()))
    rv = test_client.get(add_params_to_uri("/oauth/authorize", query))
    assert rv.data == b"ok"


def test_max_age_prompt_none(test_client):
    """With prompt=none, an authentication older than max_age gives
    login_required in the fragment."""
    auth_time = str(int(time.time()) - 7200)
    query = {
        **IMPLICIT_PARAMS,
        "max_age": "3600",
        "auth_time": auth_time,
        "prompt": "none",
    }
    rv = test_client.get(add_params_to_uri("/oauth/authorize", query))
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "login_required"


def test_max_age_invalid(test_client):
    """An invalid max_age gives invalid_request in the fragment."""
    query = {**IMPLICIT_PARAMS, "max_age": "-1"}
    rv = test_client.get(add_params_to_uri("/oauth/authorize", query))
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "invalid_request"


@pytest.mark.parametrize("authorization_session", [None], indirect=True)
def test_without_authorization_session(test_client, authorization_session):
    """Without an authorization session, a deprecation is emitted and the
    auth_time claim is the current time."""
    query = {**IMPLICIT_PARAMS, "max_age": "3600", "auth_time": "1000000000"}
    with pytest.warns(AuthlibDeprecationWarning, match="authorization session"):
        rv = test_client.get(add_params_to_uri("/oauth/authorize", query))

    assert rv.data == b"ok"

    before = int(time.time())
    rv = test_client.post("/oauth/authorize", data=query)
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    claims = validate_claims(params["id_token"], params)
    assert claims["auth_time"] >= before


def test_login_after_request_start(test_client, request_time):
    """With get_request_time, a login after the start of the request
    satisfies prompt=login."""
    params = {
        "response_type": "id_token",
        "client_id": "client-id",
        "scope": "openid profile",
        "state": "bar",
        "nonce": "abc",
        "redirect_uri": "https://client.test/callback",
        "prompt": "login",
        "user_id": "1",
    }
    rv = test_client.get(
        add_params_to_uri(
            "/oauth/authorize", {**params, "auth_time": str(int(time.time()) - 60)}
        )
    )
    assert rv.data == b"login"

    rv = test_client.get(
        add_params_to_uri(
            "/oauth/authorize", {**params, "auth_time": str(int(time.time()))}
        )
    )
    assert rv.data == b"ok"


def test_consent_required(test_client, monkeypatch):
    """With prompt=none, a needed consent gives consent_required in the
    fragment."""
    monkeypatch.setattr(
        AuthorizationSession, "is_consent_needed", lambda self, request: True
    )
    query = {**IMPLICIT_PARAMS, "prompt": "none"}
    rv = test_client.get(add_params_to_uri("/oauth/authorize", query))
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "consent_required"
