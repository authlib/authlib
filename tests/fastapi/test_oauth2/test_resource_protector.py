import pytest
from fastapi import FastAPI
from fastapi import Request
from fastapi.testclient import TestClient

from authlib.integrations.fastapi_oauth2.errors import OAuth2HTTPException
from authlib.integrations.fastapi_oauth2.resource_protector import ResourceProtector
from authlib.integrations.fastapi_oauth2.resource_protector import _call_endpoint
from authlib.integrations.fastapi_oauth2.resource_protector import _current_token
from authlib.integrations.fastapi_oauth2.resource_protector import current_token
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import MissingAuthorizationError


@pytest.fixture
def protector():
    return ResourceProtector()


@pytest.fixture
def app():
    return FastAPI()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_current_token():
    token = _current_token.set(None)
    yield
    _current_token.reset(token)


class DummyToken:
    def __init__(self, access_token="test-token", scopes=None):
        self.access_token = access_token
        self.scopes = scopes or ["profile"]


class TestRaiseErrorResponse:
    def test_raises_http_exception(self, protector):
        error = MissingAuthorizationError()

        with pytest.raises(OAuth2HTTPException) as exc_info:
            protector.raise_error_response(error)

        exc = exc_info.value

        assert exc.status_code == error.status_code
        assert exc.body is not None
        assert exc.headers is not None

    def test_error_body_is_json(self, protector):
        error = MissingAuthorizationError()

        with pytest.raises(OAuth2HTTPException) as exc_info:
            protector.raise_error_response(error)

        import json

        body = json.loads(exc_info.value.body)

        assert isinstance(body, dict)
        assert body["error"] == error.error


class TestHandleErrorResponse:
    def test_returns_response(self, protector):
        error = MissingAuthorizationError()

        response = protector.handle_error_response(error)

        assert response.status_code == error.status_code
        assert response.media_type == "application/json"

    def test_response_body_is_json(self, protector):
        import json

        error = MissingAuthorizationError()

        response = protector.handle_error_response(error)
        body = json.loads(response.body)

        assert body["error"] == error.error

    def test_response_headers(self, protector):
        error = MissingAuthorizationError()

        response = protector.handle_error_response(error)

        for key, value in error.get_headers():
            assert response.headers[key.lower()] == value


class TestAcquireToken:
    def test_requires_request(self, protector):
        with pytest.raises(RuntimeError, match="requires the"):
            protector.acquire_token()

    def test_acquires_token(self, protector, client, monkeypatch):
        token = DummyToken()

        def mock_validate_request(request, **kwargs):
            return token

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        async def endpoint(request: Request):
            result = protector.acquire_token(
                request,
                scopes=["profile"],
            )

            assert result is token
            assert current_token.access_token == "test-token"

            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_passes_scopes_to_validator(self, protector, client, monkeypatch):
        received = {}

        def mock_validate_request(request, **kwargs):
            received.update(kwargs)
            return DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        async def endpoint(request: Request):
            protector.acquire_token(request, scopes="profile")
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert received["scopes"] == ["profile"]

    def test_string_claims_are_converted_to_lists(self, protector, client, monkeypatch):
        received = {}

        def mock_validate_request(request, **kwargs):
            received.update(kwargs)
            return DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        async def endpoint(request: Request):
            protector.acquire_token(
                request,
                scopes=["profile"],
                claims="email",
            )
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert received["claims"] == ["email"]

    def test_sends_token_authenticated_signal(self, protector, client, monkeypatch):
        from authlib.integrations.fastapi_oauth2 import resource_protector

        token = DummyToken()
        calls = []

        def mock_validate_request(request, **kwargs):
            return token

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )
        monkeypatch.setattr(
            resource_protector.token_authenticated,
            "send",
            lambda sender, **kwargs: calls.append((sender, kwargs)),
        )

        @client.app.get("/test")
        async def endpoint(request: Request):
            protector.acquire_token(request)
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert len(calls) == 1
        assert calls[0][0] is protector
        assert calls[0][1]["token"] is token


class TestAcquire:
    def test_acquire_context_manager(self, protector, client, monkeypatch):
        token = DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            lambda request, **kwargs: token,
        )

        @client.app.get("/test")
        async def endpoint(request: Request):
            with protector.acquire(request, ["profile"]) as acquired:
                assert acquired is token
                assert current_token.access_token == "test-token"

            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200

    def test_handles_oauth2_error(self, protector, client, monkeypatch):
        def mock_validate_request(request, **kwargs):
            raise MissingAuthorizationError()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        async def endpoint(request: Request):
            with protector.acquire(request):
                return {"ok": True}

        @client.app.exception_handler(OAuth2HTTPException)
        async def oauth_handler(request, exc):
            from fastapi.responses import Response

            return Response(
                exc.body,
                status_code=exc.status_code,
                headers=exc.headers,
                media_type="application/json",
            )

        response = client.get("/test")

        assert response.status_code == 401
        assert response.json()["error"] == "missing_authorization"


class TestDecorator:
    def test_protected_endpoint(self, protector, client, monkeypatch):
        token = DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            lambda request, **kwargs: token,
        )

        @client.app.get("/test")
        @protector(["profile"])
        async def endpoint(request: Request):
            return {"token": current_token.access_token}

        response = client.get("/test")

        assert response.status_code == 200
        assert response.json() == {"token": "test-token"}

    def test_missing_authorization(self, protector, client, monkeypatch):
        def mock_validate_request(request, **kwargs):
            raise MissingAuthorizationError()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        @protector(["profile"])
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 401
        assert response.json()["error"] == "missing_authorization"

    def test_optional_missing_authorization(self, protector, client, monkeypatch):
        def mock_validate_request(request, **kwargs):
            raise MissingAuthorizationError()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        @protector(optional=True)
        async def endpoint(request: Request):
            return {"authenticated": False}

        response = client.get("/test")

        assert response.status_code == 200
        assert response.json() == {"authenticated": False}

    def test_optional_does_not_ignore_other_oauth_errors(
        self, protector, client, monkeypatch
    ):
        def mock_validate_request(request, **kwargs):
            raise OAuth2Error(error="invalid_token", status_code=401)

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        @protector(optional=True)
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"

    def test_callable_scopes(self, protector, client, monkeypatch):
        received = {}

        def mock_validate_request(request, **kwargs):
            received.update(kwargs)
            return DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        def dynamic_scopes(request):
            return ["profile", "email"]

        @client.app.get("/test")
        @protector(scopes=dynamic_scopes)  # <-- Use keyword argument here
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert received["scopes"] == ["profile", "email"]

    def test_sync_endpoint(self, protector, client, monkeypatch):
        monkeypatch.setattr(
            protector,
            "validate_request",
            lambda request, **kwargs: DummyToken(),
        )

        @client.app.get("/test")
        @protector()
        def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert response.json() == {"ok": True}


class TestCurrentToken:
    def test_raises_without_token(self):
        with pytest.raises(RuntimeError, match="No OAuth2 token"):
            _ = current_token.access_token

    def test_getattr(self):
        token = DummyToken()
        _current_token.set(token)

        assert current_token.access_token == "test-token"
        assert current_token.scopes == ["profile"]

    def test_repr(self):
        token = DummyToken()
        _current_token.set(token)

        assert repr(current_token) == repr(token)

    def test_getattr_propagates_missing_attribute(self):
        token = DummyToken()
        _current_token.set(token)

        with pytest.raises(AttributeError):
            _ = current_token.nonexistent


class TestCallEndpoint:
    @pytest.mark.anyio
    async def test_async_endpoint(self):
        async def endpoint():
            return {"ok": True}

        result = await _call_endpoint(endpoint)

        assert result == {"ok": True}

    @pytest.mark.anyio
    async def test_sync_endpoint(self):
        def endpoint():
            return {"ok": True}

        result = await _call_endpoint(endpoint)

        assert result == {"ok": True}

    @pytest.mark.anyio
    async def test_endpoint_arguments(self):
        async def endpoint(request, value=None):
            return {"value": value}

        result = await _call_endpoint(
            endpoint,
            request="test",
            value=42,
        )

        assert result == {"value": 42}

    def test_decorator_without_parentheses(self, protector, client, monkeypatch):
        monkeypatch.setattr(
            protector,
            "validate_request",
            lambda request, **kwargs: DummyToken(),
        )

        @client.app.get("/test")
        @protector
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_decorator_with_parentheses(self, protector, client, monkeypatch):
        monkeypatch.setattr(
            protector,
            "validate_request",
            lambda request, **kwargs: DummyToken(),
        )

        @client.app.get("/test")
        @protector()
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200

    def test_dynamic_scopes(self, protector, client, monkeypatch):
        received = {}

        def mock_validate_request(request, **kwargs):
            received.update(kwargs)
            return DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        def get_scopes(request):
            return ["profile", "email"]

        @client.app.get("/test")
        @protector(scopes=get_scopes)
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert received["scopes"] == ["profile", "email"]

    def test_dynamic_scopes_receive_request(self, protector, client, monkeypatch):
        received = {}

        def mock_validate_request(request, **kwargs):
            received.update(kwargs)
            return DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        def get_scopes(request):
            assert isinstance(request, Request)
            return ["admin"]

        @client.app.get("/test")
        @protector(scopes=get_scopes)
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert received["scopes"] == ["admin"]

    def test_static_scopes_are_preserved(self, protector, client, monkeypatch):
        received = {}

        def mock_validate_request(request, **kwargs):
            received.update(kwargs)
            return DummyToken()

        monkeypatch.setattr(
            protector,
            "validate_request",
            mock_validate_request,
        )

        @client.app.get("/test")
        @protector(["profile", "email"])
        async def endpoint(request: Request):
            return {"ok": True}

        response = client.get("/test")

        assert response.status_code == 200
        assert received["scopes"] == ["profile", "email"]
