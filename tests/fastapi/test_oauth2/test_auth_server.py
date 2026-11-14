import json
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

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
            "server": ("testserver", 443),
            "client": ("testclient", 12345),
            "scheme": "https",
        },
        receive=receive,
    )

    with patch(
        "authlib.integrations.fastapi_oauth2.authorization_server._create_oauth2_request",
        new_callable=AsyncMock,
    ) as mock_create:
        mock_create.return_value = OAuth2Request(
            "POST", "https://testserver/oauth/token"
        )
        result = await server._create_oauth2_request(request)

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

    with patch(
        "authlib.integrations.fastapi_oauth2.authorization_server._create_json_request",
        new_callable=AsyncMock,
    ) as mock_create:
        mock_create.return_value = FastApiJsonRequest(request)
        result = await server._create_json_request(request)

    assert isinstance(result, FastApiJsonRequest)


@pytest.mark.asyncio
async def test_parse_request_json(server):
    server._create_json_request = AsyncMock(return_value="json-request")

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
    server._create_json_request.assert_awaited_once_with(request)


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


def test_default_grant_type_expiration():
    generator = create_token_expires_in_generator()

    for grant_type, expected in BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN.items():
        assert generator(None, grant_type) == expected


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


@pytest.fixture
def oauth2_request():
    return OAuth2Request(
        "GET",
        "https://example.com",
    )


def test_create_oauth2_request_returns_existing_request(server, oauth2_request):
    result = server.create_oauth2_request(oauth2_request)
    assert result is oauth2_request


def test_create_json_request_returns_existing_request(server, oauth2_request):
    result = server.create_json_request(oauth2_request)
    assert result is oauth2_request


def test_create_oauth2_request_raises_type_error(server):
    with pytest.raises(TypeError, match="Expected an OAuth2Request"):
        server.create_oauth2_request(object())


def test_create_json_request_raises_type_error(server):
    with pytest.raises(TypeError, match="Expected an OAuth2Request"):
        server.create_json_request(object())


@pytest.mark.asyncio
async def test_parse_request_form_encoded(server):
    request = Mock()
    request.headers = {"content-type": "application/x-www-form-urlencoded"}
    server._create_oauth2_request = AsyncMock(return_value="oauth-request")

    result = await server._parse_request(request)

    assert result == "oauth-request"
    server._create_oauth2_request.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_create_authorization_response_without_request(server):
    with pytest.raises(TypeError, match="requires the FastAPI/Starlette"):
        await server.create_authorization_response()


@pytest.mark.asyncio
async def test_create_token_response_without_request(server):
    with pytest.raises(TypeError, match="requires the FastAPI/Starlette"):
        await server.create_token_response()


@pytest.mark.asyncio
async def test_create_authorization_response_with_parsed_request(
    server, oauth2_request
):
    grant_user = object()
    expected = Mock()

    # Оскільки super().create_authorization_response більше не асинхронний,
    # патчимо його як звичайний Mock, а не AsyncMock
    with patch(
        "authlib.oauth2.AuthorizationServer.create_authorization_response",
        return_value=expected,
    ) as create_response:
        result = await server.create_authorization_response(
            oauth2_request,
            grant_user=grant_user,
        )

    assert result is expected
    create_response.assert_called_once_with(
        oauth2_request,
        grant_user=grant_user,
    )


@pytest.mark.asyncio
async def test_create_token_response_with_parsed_request(server, oauth2_request):
    expected = Mock()

    with patch(
        "authlib.oauth2.AuthorizationServer.create_token_response",
        return_value=expected,
    ) as create_response:
        result = await server.create_token_response(oauth2_request)

    assert result is expected
    create_response.assert_called_once_with(oauth2_request)


@pytest.mark.parametrize(
    "signal_name, signal_path",
    [
        (
            "after_authenticate_client",
            "authlib.integrations.fastapi_oauth2.authorization_server.client_authenticated",
        ),
        (
            "after_revoke_token",
            "authlib.integrations.fastapi_oauth2.authorization_server.token_revoked",
        ),
    ],
)
def test_send_signal(server, signal_name, signal_path):
    with patch(f"{signal_path}.send") as mock_send:
        server.send_signal(signal_name, user="test_user", token="abc123xyz")
        mock_send.assert_called_once_with(server, user="test_user", token="abc123xyz")


def test_send_signal_unknown_name(server):
    with (
        patch(
            "authlib.integrations.fastapi_oauth2.authorization_server.client_authenticated.send"
        ) as mock_client_auth,
        patch(
            "authlib.integrations.fastapi_oauth2.authorization_server.token_revoked.send"
        ) as mock_token_revoked,
    ):
        server.send_signal("unknown_signal_name", user="test_user")
        mock_client_auth.assert_not_called()
        mock_token_revoked.assert_not_called()


@pytest.mark.asyncio
async def test_create_authorization_response_branch_coverage(server):
    raw_request = MagicMock()
    parsed_req = OAuth2Request("GET", "https://example.com/authorize")
    server._parse_request = AsyncMock(return_value=parsed_req)

    with patch(
        "authlib.oauth2.AuthorizationServer.create_authorization_response",
        new_callable=AsyncMock,
    ) as _:
        await server.create_authorization_response(
            request=raw_request, grant_user=MagicMock()
        )
        server._parse_request.assert_awaited_once_with(raw_request)

    valid_oauth_req = OAuth2Request("GET", "https://example.com/authorize")
    server._parse_request.reset_mock()

    with patch(
        "authlib.oauth2.AuthorizationServer.create_authorization_response",
        new_callable=AsyncMock,
    ) as _:
        await server.create_authorization_response(
            request=valid_oauth_req, grant_user=MagicMock()
        )
        server._parse_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_token_response_branch_coverage(server):
    raw_request = MagicMock()
    parsed_req = OAuth2Request("POST", "https://example.com/token")
    server._parse_request = AsyncMock(return_value=parsed_req)

    with patch(
        "authlib.oauth2.AuthorizationServer.create_token_response",
        new_callable=AsyncMock,
    ) as _:
        await server.create_token_response(request=raw_request)
        server._parse_request.assert_awaited_once_with(raw_request)

    valid_oauth_req = OAuth2Request("POST", "https://example.com/token")
    server._parse_request.reset_mock()

    with patch(
        "authlib.oauth2.AuthorizationServer.create_token_response",
        new_callable=AsyncMock,
    ) as _:
        await server.create_token_response(request=valid_oauth_req)
        server._parse_request.assert_not_awaited()


def test_get_error_uri_success(server):
    server._error_uris = {
        "invalid_request": "https://example.com/errors/invalid-request",
    }
    request = Mock()
    error = Mock()
    error.error = "invalid_request"

    result = server.get_error_uri(request, error)
    assert result == "https://example.com/errors/invalid-request"


def test_get_error_uri_not_found(server):
    server._error_uris = {
        "invalid_request": "https://example.com/errors/invalid-request",
    }
    request = Mock()
    error = Mock()
    error.error = "unknown_error"

    result = server.get_error_uri(request, error)
    assert result is None


def test_get_error_uri_no_config(server):
    server._error_uris = None
    request = Mock()
    error = Mock()
    error.error = "invalid_request"

    result = server.get_error_uri(request, error)
    assert result is None


# --- Тести для _create_json_request ---
@pytest.mark.asyncio
async def test_create_json_request_with_oauth2_request(server):
    oauth2_req = OAuth2Request("POST", "https://example.com/token")
    result = await server._create_json_request(oauth2_req)
    assert result is oauth2_req


@pytest.mark.asyncio
async def test_create_json_request_with_starlette_request(server):
    request = Mock()
    # Виправляємо ініціалізацію: FastApiJsonRequest очікує лише request
    expected_req = FastApiJsonRequest(request)

    with patch(
        "authlib.integrations.fastapi_oauth2.authorization_server._create_json_request",
        new_callable=AsyncMock,
        return_value=expected_req,
    ) as mock_create:
        result = await server._create_json_request(request)

    assert result is expected_req
    mock_create.assert_awaited_once_with(request)


# --- Тести для _create_oauth2_request ---
@pytest.mark.asyncio
async def test_create_oauth2_request_with_oauth2_request(server):
    oauth2_req = OAuth2Request("POST", "https://example.com/token")
    result = await server._create_oauth2_request(oauth2_req)
    assert result is oauth2_req


@pytest.mark.asyncio
async def test_create_oauth2_request_with_starlette_request(server):
    request = Mock()
    expected_req = OAuth2Request("POST", "https://example.com/token")

    with patch(
        "authlib.integrations.fastapi_oauth2.authorization_server._create_oauth2_request",
        new_callable=AsyncMock,
        return_value=expected_req,
    ) as mock_create:
        result = await server._create_oauth2_request(request)

    assert result is expected_req
    mock_create.assert_awaited_once_with(request)


# --- Тести для handle_response ---
def test_handle_response_with_dict_payload_and_list_headers(server):
    payload = {"access_token": "token123", "token_type": "Bearer"}
    headers = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]

    response = server.handle_response(200, payload, headers)

    assert isinstance(response, Response)
    assert response.status_code == 200
    assert json.loads(response.body) == payload
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_handle_response_with_string_payload_and_dict_headers(server):
    payload = "error_description"
    headers = {"Content-Type": "text/plain"}

    response = server.handle_response(400, payload, headers)

    assert isinstance(response, Response)
    assert response.status_code == 400
    assert response.body == b"error_description"
    assert response.headers["content-type"] == "text/plain"
