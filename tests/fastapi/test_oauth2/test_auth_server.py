import json
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi import Request
from fastapi import Response

from authlib.integrations.fastapi_oauth2.authorization_server import AuthorizationServer
from authlib.integrations.fastapi_oauth2.authorization_server import (
    create_token_expires_in_generator,
)
from authlib.integrations.fastapi_oauth2.authorization_server import (
    create_token_generator,
)
from authlib.integrations.fastapi_oauth2.authorization_server import import_string
from authlib.integrations.fastapi_oauth2.requests import FastApiJsonRequest
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6750 import BearerTokenGenerator


def test_init_without_config():
    server = AuthorizationServer()

    assert server._query_client is None
    assert server._save_token is None
    assert server._error_uris is None


def test_init_with_config(server):
    assert server.scopes_supported == ["openid", "profile", "email"]


def test_init_app(config, query_client, save_token):
    server = AuthorizationServer()

    server.init_app(config, query_client, save_token)

    assert server._query_client is query_client
    assert server._save_token is save_token
    assert server.scopes_supported == ["openid", "profile", "email"]


def test_init_app_preserves_existing_callbacks(
    config,
    query_client,
    save_token,
):
    server = AuthorizationServer(config, query_client, save_token)

    server.init_app(config)

    assert server._query_client is query_client
    assert server._save_token is save_token


def test_query_client(server):
    result = server.query_client("client-123")

    assert result == {"client_id": "client-123"}


def test_save_token(server):
    token = {"access_token": "test-token"}
    request = object()

    result = server.save_token(token, request)

    assert result is None


def test_query_client_calls_callback():
    callback = Mock(return_value="client")

    server = AuthorizationServer(
        query_client=callback,
    )

    result = server.query_client("client-123")

    assert result == "client"
    callback.assert_called_once_with("client-123")


def test_save_token_calls_callback():
    callback = Mock()

    server = AuthorizationServer(save_token=callback)

    token = {"access_token": "abc"}
    request = object()

    server.save_token(token, request)

    callback.assert_called_once_with(token, request)


def test_import_string_with_dot():
    result = import_string("json.dumps")

    assert result is json.dumps


def test_import_string_with_colon():
    result = import_string("json:dumps")

    assert result is json.dumps


def test_import_string_with_callable():
    def callback():
        pass

    assert import_string(callback) is callback


def test_import_string_invalid_format():
    with pytest.raises(ImportError):
        import_string("invalid")


def test_import_string_module_not_found():
    with pytest.raises(ModuleNotFoundError):
        import_string("nonexistent_module.function")


def test_import_string_attribute_not_found():
    with pytest.raises(ImportError):
        import_string("json.nonexistent_function")


def test_create_token_generator_callable():
    callback = Mock(return_value="custom-token")

    generator = create_token_generator(callback)

    assert generator() == "custom-token"
    callback.assert_called_once()


def test_create_token_generator_import_string():
    generator = create_token_generator("json.dumps")

    assert generator({"a": 1}) == '{"a": 1}'


def test_create_token_generator_true():
    generator = create_token_generator(True)

    token = generator()

    assert isinstance(token, str)
    assert len(token) == 42


def test_create_token_generator_custom_length():
    generator = create_token_generator(True, length=64)

    token = generator()

    assert len(token) == 64


def test_create_token_generator_false():
    generator = create_token_generator(False)

    assert generator is None


def test_default_expires_in():
    generator = create_token_expires_in_generator()

    result = generator(None, "unknown_grant")

    assert result == BearerTokenGenerator.DEFAULT_EXPIRES_IN


def test_custom_expires_in():
    generator = create_token_expires_in_generator(
        {
            "authorization_code": 3600,
            "client_credentials": 1800,
        }
    )

    assert generator(None, "authorization_code") == 3600
    assert generator(None, "client_credentials") == 1800


def test_default_grant_type_expires_in():
    generator = create_token_expires_in_generator()

    expected = BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN

    for grant_type, expires_in in expected.items():
        assert generator(None, grant_type) == expires_in


# def test_custom_expires_in_overrides_default():
#     generator = create_token_expires_in_generator(
#         {
#             "authorization_code": 7200,
#         }
#     )
#
#     assert generator(None, "authorization_code") == 7200


def test_expires_in_import_string(monkeypatch):
    def dummy_expires_in(client, grant_type):
        return 3600

    from authlib.integrations.fastapi_oauth2 import authorization_server

    monkeypatch.setattr(
        authorization_server, "import_string", lambda s: dummy_expires_in
    )

    generator = create_token_expires_in_generator(
        "app.oauth2.generators.custom_expires_in"
    )

    assert callable(generator)


@pytest.fixture
def app():
    return FastAPI()


@pytest.mark.asyncio
async def test_create_oauth2_request(app):
    server = AuthorizationServer()

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/oauth/token",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
            ],
            "query_string": b"",
            "server": ("testserver", 443),  # Optionally use 443 for HTTPS
            "client": ("testclient", 12345),
            "scheme": "https",  # <-- Change from "http" to "https"
        },
        receive=receive,
    )

    result = await server.create_oauth2_request(request)

    assert isinstance(result, OAuth2Request)


@pytest.mark.asyncio
async def test_create_json_request(app):
    server = AuthorizationServer()

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/oauth/token",
            "headers": [
                (b"content-type", b"application/json"),
            ],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("testclient", 12345),
            "scheme": "http",
        }
    )

    result = await server.create_json_request(request)

    assert isinstance(result, FastApiJsonRequest)


@pytest.mark.asyncio
async def test_parse_request_json(server):
    from unittest.mock import AsyncMock

    server.create_json_request = AsyncMock(return_value="json-request")

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/oauth/token",
            "headers": [(b"content-type", b"application/json")],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("testclient", 12345),
            "scheme": "http",
        }
    )

    result = await server._parse_request(request)

    assert result == "json-request"
    server.create_json_request.assert_awaited_once_with(request)


def test_handle_response_dict(server):
    payload = {"access_token": "abc", "token_type": "Bearer"}

    response = server.handle_response(
        200,
        payload,
        {"Cache-Control": "no-store"},
    )

    assert isinstance(response, Response)
    assert response.status_code == 200
    assert json.loads(response.body) == payload
    assert response.headers["cache-control"] == "no-store"


def test_handle_response_string(server):
    response = server.handle_response(
        400,
        "invalid_request",
        {},
    )

    assert response.status_code == 400
    assert response.body == b"invalid_request"


def test_get_error_uri(server):
    server._error_uris = {
        "invalid_request": "https://example.com/errors/invalid-request",
    }

    request = Mock()
    error = Mock()
    error.error = "invalid_request"

    result = server.get_error_uri(request, error)

    assert result == "https://example.com/errors/invalid-request"


def test_get_error_uri_unknown_error(server):
    server._error_uris = {
        "invalid_request": "https://example.com/errors/invalid-request",
    }

    request = Mock()
    error = Mock()
    error.error = "invalid_client"

    assert server.get_error_uri(request, error) is None


def test_get_error_uri_without_config(server):
    request = Mock()
    error = Mock()

    assert server.get_error_uri(request, error) is None


# def test_default_expires_in():
#     generator = create_token_expires_in_generator()
#
#     assert generator(None, "unknown_grant") == (BearerTokenGenerator.DEFAULT_EXPIRES_IN)


def test_default_grant_type_expiration():
    generator = create_token_expires_in_generator()

    for grant_type, expected in BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN.items():
        assert generator(None, grant_type) == expected


# def test_custom_expires_in():
#     generator = create_token_expires_in_generator(
#         {
#             "authorization_code": 3600,
#             "client_credentials": 1800,
#         }
#     )
#
#     assert generator(None, "authorization_code") == 3600
#     assert generator(None, "client_credentials") == 1800


def test_custom_expiration_overrides_default():
    generator = create_token_expires_in_generator(
        {
            "authorization_code": 7200,
        }
    )

    assert generator(None, "authorization_code") == 7200


def test_unknown_grant_type_uses_default():
    generator = create_token_expires_in_generator({})

    assert generator(None, "unknown_grant") == (BearerTokenGenerator.DEFAULT_EXPIRES_IN)


def test_import_string():
    generator = create_token_expires_in_generator("json.dumps")

    assert generator is json.dumps


def test_custom_config_does_not_mutate_defaults():
    defaults = BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN.copy()

    create_token_expires_in_generator(
        {
            "authorization_code": 7200,
        }
    )

    assert BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN == defaults


@pytest.mark.parametrize("config", [None, {}, [], 123, True])
def test_non_dict_config_uses_default_expirations(config):
    generator = create_token_expires_in_generator(config)

    assert generator(None, "unknown_grant") == (BearerTokenGenerator.DEFAULT_EXPIRES_IN)
