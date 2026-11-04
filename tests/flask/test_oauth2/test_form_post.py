import pytest

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.form_post import FormPost
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.rfc6749 import AuthorizationResponse
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import OAuth2Response
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import ImplicitGrant
from authlib.oidc.core.grants.util import create_response_mode_response
from tests.util import parse_form

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import register_form_post

authorize_url = "/oauth/authorize?client_id=client-id&state=bar"


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class FormPostCodeGrant(AuthorizationCodeGrant):
    RESPONSE_MODE = "form_post"


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": [
                "https://client.test/authorized",
                "javascript://client.test/%0Aalert(1)",
            ],
            "scope": "profile",
            "response_types": ["code", "token"],
            "grant_types": ["authorization_code", "implicit"],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def add_header(server, response):
    response.headers.append(("X-Custom", "value"))


@pytest.mark.parametrize(
    "grant_cls,response_type,param",
    [
        (AuthorizationCodeGrant, "code", "code"),
        (ImplicitGrant, "token", "access_token"),
    ],
)
@pytest.mark.parametrize("user_id", ["1", ""])
def test_form_post(test_client, server, grant_cls, response_type, param, user_id):
    """Any grant can send its response, or its denial, with an HTML form.
    Clients and proxies must not cache it."""
    server.register_grant(grant_cls)
    register_form_post(server)
    server.register_hook(
        add_header, before=AuthorizationServer.encode_authorization_response
    )

    rv = test_client.post(
        f"{authorize_url}&response_type={response_type}&response_mode=form_post",
        data={"user_id": user_id},
    )

    assert rv.status_code == 200
    assert rv.headers["Cache-Control"] == "no-store"
    assert rv.headers["Pragma"] == "no-cache"
    assert rv.headers["X-Custom"] == "value"
    form = parse_form(rv.data)
    assert form.action == "https://client.test/authorized"
    assert form.values["state"] == "bar"
    assert (param in form.values) is bool(user_id)
    assert ("error" in form.values) is not bool(user_id)


@pytest.mark.parametrize(
    "grant_cls,response_mode",
    [
        (AuthorizationCodeGrant, "&response_mode=form_post"),
        (FormPostCodeGrant, ""),
    ],
)
def test_non_http_redirect_uri(test_client, server, grant_cls, response_mode):
    """No form is rendered for a non-HTTP redirect URI, whether form_post is
    requested or is the default response mode of the grant."""
    server.register_grant(grant_cls)
    register_form_post(server)

    rv = test_client.post(
        f"{authorize_url}&response_type=code{response_mode}"
        "&redirect_uri=javascript://client.test/%250Aalert(1)",
        data={"user_id": "1"},
    )

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert b"<form" not in rv.data


def test_encode_refuses_non_http_redirect_uri():
    """The form is never rendered for a non-HTTP redirect URI, even when the
    request was not validated."""
    response = AuthorizationResponse(
        "javascript://client.test/%0Aalert(1)", [("code", "x")], "form_post"
    )

    with pytest.raises(InvalidRequestError):
        FormPost().encode(response)


@pytest.mark.parametrize("user_id", ["1", ""])
def test_default_form_post(test_client, server, user_id):
    """A grant can use form_post by default, for its responses and its
    denials."""
    server.register_grant(FormPostCodeGrant)
    register_form_post(server)

    rv = test_client.post(
        f"{authorize_url}&response_type=code", data={"user_id": user_id}
    )

    form = parse_form(rv.data)
    assert form.values["state"] == "bar"
    assert ("code" in form.values) is bool(user_id)
    assert ("error" in form.values) is not bool(user_id)


def test_default_form_post_non_http_redirect_uri_with_unsupported_mode(
    test_client, server
):
    """An unsupported response mode error is not sent with a default
    form_post to a non-HTTP redirect URI."""
    server.register_grant(FormPostCodeGrant)
    register_form_post(server)

    rv = test_client.post(
        f"{authorize_url}&response_type=code&response_mode=unknown"
        "&redirect_uri=javascript://client.test/%250Aalert(1)",
        data={"user_id": "1"},
    )

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert b"<form" not in rv.data


def test_default_form_post_without_form_post_mode(test_client, server):
    """A default form_post needs FormPost in the extension."""
    server.register_grant(FormPostCodeGrant)
    server.register_extension(MultipleResponseTypes())

    with pytest.raises(RuntimeError, match="form_post"):
        test_client.post(f"{authorize_url}&response_type=code", data={"user_id": "1"})


@pytest.mark.parametrize(
    "response_mode,response_cls",
    [("form_post", OAuth2Response), ("fragment", AuthorizationResponse)],
)
def test_create_response_mode_response_is_deprecated(response_mode, response_cls):
    with pytest.warns(AuthlibDeprecationWarning, match="AuthorizationResponse"):
        response = create_response_mode_response(
            "https://client.test/authorized", [("code", "x")], response_mode
        )

    assert type(response) is response_cls
