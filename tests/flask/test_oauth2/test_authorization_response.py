from urllib.parse import urlparse

import pytest

from authlib.common.urls import url_decode
from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749 import AuthorizationResponse
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import OAuth2Response
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import ImplicitGrant

from .models import CodeGrantMixin
from .models import save_authorization_code

authorize_url = "/oauth/authorize?client_id=client-id&state=bar"


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class UnpackingGrant(AuthorizationCodeGrant):
    def create_authorization_response(self, redirect_uri, grant_user):
        status_code, body, headers = super().create_authorization_response(
            redirect_uri, grant_user
        )
        return OAuth2Response(status_code, body, headers + [("X-Custom", "value")])


class FormPostGrant(AuthorizationCodeGrant):
    def create_authorization_response(self, redirect_uri, grant_user):
        return AuthorizationResponse(redirect_uri, [("code", "x")], "form_post")


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "response_types": ["code", "token"],
            "grant_types": ["authorization_code", "implicit"],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def change_response(server, response):
    response.status_code = 302
    response.params.append(("extra", "value"))
    response.headers.append(("X-Custom", "value"))


def get_params(location, response_type):
    parsed = urlparse(location)
    component = parsed.fragment if response_type == "token" else parsed.query
    return dict(url_decode(component))


@pytest.mark.parametrize(
    "grant_cls,response_type",
    [(AuthorizationCodeGrant, "code"), (ImplicitGrant, "token")],
)
@pytest.mark.parametrize("user_id", ["1", ""])
def test_hook_changes_the_response(
    test_client, server, grant_cls, response_type, user_id
):
    """A hook on encode_authorization_response changes the status code, the
    parameters and the headers of the response, granted or denied."""
    server.register_grant(grant_cls)
    server.register_hook(
        change_response, before=AuthorizationServer.encode_authorization_response
    )

    rv = test_client.post(
        f"{authorize_url}&response_type={response_type}", data={"user_id": user_id}
    )

    params = get_params(rv.location, response_type)
    assert params["extra"] == "value"
    assert params["state"] == "bar"
    assert ("error" in params) is not bool(user_id)
    assert rv.status_code == 302
    assert rv.headers["X-Custom"] == "value"


def test_hook_changes_consent_errors(test_client, server, client, db):
    """The hook also applies to errors from get_consent_grant."""
    server.register_grant(AuthorizationCodeGrant)
    server.register_hook(
        change_response, before=AuthorizationServer.encode_authorization_response
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "response_types": ["token"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.get(f"{authorize_url}&response_type=code&user_id=1")

    params = get_params(rv.location, "code")
    assert params["error"] == "unauthorized_client"
    assert params["extra"] == "value"


def test_unpacking_the_response_is_deprecated(test_client, server):
    """A grant can still unpack the response of its parent as a tuple."""
    server.register_grant(UnpackingGrant)

    with pytest.warns(AuthlibDeprecationWarning, match="tuple is deprecated"):
        rv = test_client.post(
            f"{authorize_url}&response_type=code", data={"user_id": "1"}
        )

    assert rv.headers["X-Custom"] == "value"
    assert "code" in get_params(rv.location, "code")


def test_unsupported_response_mode(test_client, server):
    """An unknown response mode raises an error instead of using the query."""
    server.register_grant(FormPostGrant)

    with pytest.raises(ValueError, match="form_post"):
        test_client.post(f"{authorize_url}&response_type=code", data={"user_id": "1"})
