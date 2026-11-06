import pytest
from flask import json

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import JsonResponse
from authlib.oauth2.rfc6749 import OAuth2Response
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header

token_data = {"grant_type": "client_credentials"}


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class UnpackingGrant(ClientCredentialsGrant):
    def create_token_response(self):
        status_code, token, headers = super().create_token_response()
        return OAuth2Response(status_code, {**token, "custom": "value"}, headers)


class IndexingGrant(ClientCredentialsGrant):
    def create_token_response(self):
        response = super().create_token_response()
        assert response[0] == 200
        return JsonResponse({**response[1], "custom": "value"})


class TupleGrant(ClientCredentialsGrant):
    def create_token_response(self):
        return 200, {"custom": "value"}, [("Content-Type", "application/json")]


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "response_types": ["code"],
            "grant_types": ["client_credentials", "authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def add_header(server, response):
    response.headers.append(("X-Custom", "value"))


def post_token(test_client, secret="client-secret"):
    headers = create_basic_header("client-id", secret)
    return test_client.post("/oauth/token", data=token_data, headers=headers)


@pytest.mark.parametrize(
    "secret,status_code", [("client-secret", 200), ("invalid-secret", 401)]
)
def test_hook_changes_token_responses(test_client, server, secret, status_code):
    """A hook on encode_response changes token responses and errors."""
    server.register_grant(ClientCredentialsGrant)
    server.register_hook(add_header, before=AuthorizationServer.encode_response)

    rv = post_token(test_client, secret)

    assert rv.status_code == status_code
    assert rv.headers["X-Custom"] == "value"


@pytest.mark.parametrize("user_id,param", [("1", "code="), ("", "error=")])
def test_hook_changes_authorization_responses(test_client, server, user_id, param):
    """A hook on encode_response changes authorization responses and error
    redirections."""
    server.register_grant(AuthorizationCodeGrant)
    server.register_hook(add_header, before=AuthorizationServer.encode_response)

    rv = test_client.post(
        "/oauth/authorize?response_type=code&client_id=client-id",
        data={"user_id": user_id},
    )

    assert param in rv.location
    assert rv.headers["X-Custom"] == "value"


def test_hook_changes_only_one_response(test_client, server):
    """A hook that changes the headers of a response does not change the
    headers of the next responses."""
    responses = []

    def add_header_once(server, response):
        if not responses:
            add_header(server, response)
        responses.append(response)

    server.register_grant(ClientCredentialsGrant)
    server.register_hook(add_header_once, before=AuthorizationServer.encode_response)

    first = post_token(test_client)
    second = post_token(test_client)

    assert first.headers["X-Custom"] == "value"
    assert "X-Custom" not in second.headers


@pytest.mark.parametrize("grant_cls", [UnpackingGrant, IndexingGrant])
def test_using_the_response_as_a_tuple_is_deprecated(test_client, server, grant_cls):
    """A grant can still use the response of its parent as a tuple. It gets
    one warning per response."""
    server.register_grant(grant_cls)

    with pytest.warns(AuthlibDeprecationWarning, match="tuple is deprecated") as record:
        rv = post_token(test_client)

    assert len(record) == 1

    resp = json.loads(rv.data)
    assert resp["custom"] == "value"
    assert "access_token" in resp


def test_grant_returning_a_tuple(test_client, server):
    """Returning a (status_code, body, headers) tuple is deprecated.

    The hooks on encode_response also apply to it.
    """
    server.register_grant(TupleGrant)
    server.register_hook(add_header, before=AuthorizationServer.encode_response)

    with pytest.warns(AuthlibDeprecationWarning, match="Returning a"):
        rv = post_token(test_client)

    assert json.loads(rv.data) == {"custom": "value"}
    assert rv.headers["X-Custom"] == "value"
