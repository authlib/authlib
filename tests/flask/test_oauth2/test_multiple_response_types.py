from urllib.parse import urlparse

import pytest

from authlib.common.urls import url_decode
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.multiple_response_types import ResponseMode
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import JsonResponse
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


class JsonResponseMode(ResponseMode):
    RESPONSE_MODES = ["json"]

    def validate(self, grant, redirect_uri):
        if "forbidden" in redirect_uri:
            raise InvalidRequestError(
                "The redirect URI cannot use 'json'.", redirect_uri=redirect_uri
            )

    def encode(self, response):
        return JsonResponse(dict(response.params))


class ResponseModes(MultipleResponseTypes):
    def __init__(self, response_modes_supported=None, response_modes=None):
        super().__init__(response_modes)
        self.response_modes_supported = response_modes_supported

    def get_server_metadata(self):
        if self.response_modes_supported is None:
            return {}

        return {"response_modes_supported": self.response_modes_supported}


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(ImplicitGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": [
                "https://client.test/authorized",
                "https://client.test/forbidden",
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


def authorize(test_client, response_type, response_mode=None, **data):
    url = f"{authorize_url}&response_type={response_type}"
    if response_mode:
        url += f"&response_mode={response_mode}"

    return test_client.post(url, data={"user_id": "1", **data})


def get_params(location):
    parsed = urlparse(location)
    return {
        "query": dict(url_decode(parsed.query)),
        "fragment": dict(url_decode(parsed.fragment)),
    }


@pytest.mark.parametrize("user_id", ["1", ""])
def test_code_in_fragment(test_client, server, user_id):
    """A client can receive the code, or the denial, in the fragment."""
    server.register_extension(MultipleResponseTypes())

    rv = authorize(test_client, "code", "fragment", user_id=user_id)

    params = get_params(rv.location)
    assert not params["query"]
    assert params["fragment"]["state"] == "bar"
    assert ("code" in params["fragment"]) is bool(user_id)


@pytest.mark.parametrize(
    "response_type,default", [("code", "query"), ("token", "fragment")]
)
def test_default_response_mode(test_client, server, response_type, default):
    """Without response_mode, the response uses the default mode of the
    response type."""
    server.register_extension(MultipleResponseTypes())

    rv = authorize(test_client, response_type)

    params = get_params(rv.location)
    assert params[default]["state"] == "bar"


def test_response_mode_ignored_without_extension(test_client):
    """Without the extension, the response_mode parameter is ignored."""
    rv = authorize(test_client, "code", "fragment")

    params = get_params(rv.location)
    assert "code" in params["query"]
    assert not params["fragment"]


def test_multiple_response_mode(test_client, server):
    """With the extension, a repeated response_mode gives an invalid_request
    error."""
    server.register_extension(MultipleResponseTypes())

    rv = test_client.get(
        f"{authorize_url}&response_type=code&response_mode=query&response_mode=fragment"
    )

    assert rv.json["error"] == "invalid_request"
    assert rv.json["error_description"] == "Multiple 'response_mode' in request."


def test_validation_errors_use_the_default_response_mode(test_client, server):
    """The requested response mode is not used before the request is
    validated."""
    server.register_extension(MultipleResponseTypes())
    server.scopes_supported = ["profile"]

    rv = authorize(test_client, "code", "fragment", scope="unknown")

    params = get_params(rv.location)
    assert params["query"]["error"] == "invalid_scope"
    assert params["query"]["state"] == "bar"


@pytest.mark.parametrize(
    "response_type,response_mode,default",
    [
        ("token", "query", "fragment"),
        ("code", "unknown", "query"),
        ("token", "unknown", "fragment"),
    ],
)
def test_unsupported_response_mode(
    test_client, server, response_type, response_mode, default
):
    """Per MRT §7, tokens never go in the query. Unknown modes are refused.
    The error uses the default response mode of the response type."""
    server.register_extension(MultipleResponseTypes())

    rv = authorize(test_client, response_type, response_mode)

    params = get_params(rv.location)[default]
    assert params["error"] == "invalid_request"
    assert params["state"] == "bar"
    assert "access_token" not in rv.location


def test_response_modes_supported(test_client, server):
    """The server refuses the modes missing from response_modes_supported."""
    server.register_extension(ResponseModes(response_modes_supported=["query"]))

    rv = authorize(test_client, "code", "fragment")

    params = get_params(rv.location)
    assert params["query"]["error"] == "invalid_request"


@pytest.mark.parametrize("user_id", ["1", ""])
def test_custom_response_mode(test_client, server, user_id):
    """A response mode passed to the extension encodes the responses."""
    server.register_extension(
        ResponseModes(
            response_modes_supported=["query", "fragment", "json"],
            response_modes=[JsonResponseMode()],
        )
    )

    rv = authorize(test_client, "code", "json", user_id=user_id)

    assert rv.status_code == 200
    assert rv.json["state"] == "bar"
    assert ("code" in rv.json) is bool(user_id)


def test_custom_response_mode_validation(test_client, server):
    """A response mode can refuse a request. The error uses the default
    response mode."""
    server.register_extension(
        ResponseModes(
            response_modes_supported=["query", "json"],
            response_modes=[JsonResponseMode()],
        )
    )

    rv = authorize(
        test_client,
        "code",
        "json",
        redirect_uri="https://client.test/forbidden",
    )

    params = get_params(rv.location)
    assert params["query"]["error"] == "invalid_request"


def test_supported_response_mode_without_encoder(test_client, server):
    """A mode listed in the metadata but that nothing encodes is refused."""
    server.register_extension(ResponseModes(response_modes_supported=["query", "json"]))

    rv = authorize(test_client, "code", "json")

    params = get_params(rv.location)
    assert params["query"]["error"] == "invalid_request"


def test_response_mode_encode_is_abstract():
    with pytest.raises(NotImplementedError):
        ResponseMode().encode(None)
