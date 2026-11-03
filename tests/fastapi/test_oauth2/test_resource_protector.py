import importlib
from contextvars import ContextVar
from types import SimpleNamespace

import pytest
from fastapi import Depends
from fastapi import FastAPI
from fastapi import Request
from fastapi.testclient import TestClient

from authlib.integrations.base_client import InvalidTokenError
from authlib.integrations.fastapi_oauth2.errors import OAuth2HTTPException
from authlib.integrations.fastapi_oauth2.resource_protector import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError as OAuthInvalidTokenError

module = importlib.import_module(
    "authlib.integrations.fastapi_oauth2.resource_protector"
)


class DummyToken:
    def __init__(
        self,
        user_id,
        client_id,
        scopes,
        revoked=False,
    ):
        self.user_id = user_id
        self.client_id = client_id
        self.scopes = scopes
        self.revoked = revoked

    def is_revoked(self):
        return self.revoked

    def is_expired(self):
        return False


class DummyBearerTokenValidator(BearerTokenValidator):
    tokens = {
        "valid-token-profile": DummyToken(
            user_id=1,
            client_id="client-1",
            scopes=["profile", "read"],
        ),
        "valid-token-another-user": DummyToken(
            user_id=3,
            client_id="client-3",
            scopes=["profile", "read"],
        ),
        "valid-token-read-only": DummyToken(
            user_id=2,
            client_id="client-2",
            scopes=["read"],
        ),
        "revoked-token": DummyToken(
            user_id=4,
            client_id="client-4",
            scopes=["profile"],
            revoked=True,
        ),
    }

    def authenticate_token(self, token_string):
        return self.tokens.get(token_string)

    def validate_token(self, token, scopes, request):
        if token is None or token.is_revoked():
            raise OAuthInvalidTokenError()

        if not set(scopes).issubset(set(token.scopes)):
            raise InsufficientScopeError()


@pytest.fixture
def app():
    app = FastAPI()
    protector = ResourceProtector()
    protector.register_token_validator(DummyBearerTokenValidator())

    @app.get("/profile")
    async def profile(
        token=Depends(protector(["profile"])),  # noqa: B008
    ):
        return {
            "user_id": token.user_id,
            "client_id": token.client_id,
        }

    @app.get("/optional-profile")
    async def optional_profile(
        token=Depends(protector(["profile"], optional=True)),  # noqa: B008
    ):
        if token is None:
            return {"authenticated": False}

        return {
            "authenticated": True,
            "user_id": token.user_id,
        }

    @app.get("/dynamic-scope")
    async def dynamic_scope(
        request: Request,
        token=Depends(  # noqa: B008
            protector(  # noqa: B008
                lambda request: [request.query_params.get("scope", "profile")]
            )
        ),
    ):
        return {"user_id": token.user_id}

    @app.get("/request-state")
    async def request_state(
        request: Request,
        token=Depends(protector(["profile"])),  # noqa: B008
    ):
        return {
            "same_token": request.state.oauth2_token is token,
            "user_id": request.state.oauth2_token.user_id,
        }

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_valid_token(client):
    response = client.get(
        "/profile",
        headers={"Authorization": "Bearer valid-token-profile"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "user_id": 1,
        "client_id": "client-1",
    }


def test_missing_authorization_header(client):
    response = client.get("/profile")

    assert response.status_code == 401


def test_invalid_token(client):
    response = client.get(
        "/profile",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_revoked_token(client):
    response = client.get(
        "/profile",
        headers={"Authorization": "Bearer revoked-token"},
    )

    assert response.status_code == 401


def test_insufficient_scope(client):
    response = client.get(
        "/profile",
        headers={"Authorization": "Bearer valid-token-read-only"},
    )

    assert response.status_code == 403


def test_optional_dependency_without_token(client):
    response = client.get("/optional-profile")

    assert response.status_code == 200
    assert response.json() == {"authenticated": False}


def test_optional_dependency_with_token(client):
    response = client.get(
        "/optional-profile",
        headers={"Authorization": "Bearer valid-token-profile"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": True,
        "user_id": 1,
    }


def test_callable_scopes(client):
    response = client.get(
        "/dynamic-scope?scope=profile",
        headers={"Authorization": "Bearer valid-token-profile"},
    )

    assert response.status_code == 200
    assert response.json() == {"user_id": 1}


def test_callable_scopes_reject_insufficient_scope(client):
    response = client.get(
        "/dynamic-scope?scope=admin",
        headers={"Authorization": "Bearer valid-token-profile"},
    )

    assert response.status_code == 403


def test_token_is_stored_in_request_state(client):
    response = client.get(
        "/request-state",
        headers={"Authorization": "Bearer valid-token-profile"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "same_token": True,
        "user_id": 1,
    }


def test_handle_error_response():
    protector = ResourceProtector()

    response = protector.handle_error_response(OAuthInvalidTokenError())

    assert response.status_code == 401
    assert response.media_type == "application/json"


def test_raise_error_response():
    protector = ResourceProtector()

    with pytest.raises(OAuth2HTTPException) as exc:
        protector.raise_error_response(OAuthInvalidTokenError())

    assert exc.value.status_code == 401


@pytest.mark.anyio
async def test_call_endpoint_sync():
    def endpoint(value):
        return value

    result = await module._call_endpoint(endpoint, "test")

    assert result == "test"


@pytest.mark.anyio
async def test_call_endpoint_async():
    async def endpoint(value):
        return value

    result = await module._call_endpoint(endpoint, "test")

    assert result == "test"


def test_current_token_without_request(monkeypatch):
    request_context = ContextVar("request", default=None)
    monkeypatch.setattr(module, "_current_request", request_context, raising=False)

    with pytest.raises(RuntimeError, match="No request found"):
        _ = module.current_token.user_id


def test_current_token_without_oauth2_token(monkeypatch):
    request_context = ContextVar("request", default=None)
    monkeypatch.setattr(module, "_current_request", request_context, raising=False)

    request_context.set(SimpleNamespace(state=SimpleNamespace()))

    with pytest.raises(RuntimeError, match="No OAuth2 token found"):
        _ = module.current_token.user_id


def test_current_token_getattr(monkeypatch):
    request_context = ContextVar("request", default=None)
    monkeypatch.setattr(module, "_current_request", request_context, raising=False)

    token = SimpleNamespace(user_id=42)
    request_context.set(SimpleNamespace(state=SimpleNamespace(oauth2_token=token)))

    assert module.current_token.user_id == 42


def test_current_token_repr(monkeypatch):
    request_context = ContextVar("request", default=None)
    monkeypatch.setattr(module, "_current_request", request_context, raising=False)

    token = SimpleNamespace(user_id=42)
    request_context.set(SimpleNamespace(state=SimpleNamespace(oauth2_token=token)))

    assert repr(module.current_token) == repr(token)


def test_validate_token_valid():
    protector = ResourceProtector()
    token = DummyToken(1, "client-1", ["profile", "read"])

    protector.validate_token(token, ["profile"], None)


def test_validate_token_missing_token():
    protector = ResourceProtector()

    with pytest.raises(InvalidTokenError):
        protector.validate_token(None, ["profile"], None)


def test_validate_token_revoked_token():
    protector = ResourceProtector()
    token = DummyToken(1, "client-1", ["profile"], revoked=True)

    with pytest.raises(InvalidTokenError):
        protector.validate_token(token, ["profile"], None)


def test_validate_token_insufficient_scope():
    protector = ResourceProtector()
    token = DummyToken(1, "client-1", ["read"])

    with pytest.raises(InsufficientScopeError):
        protector.validate_token(token, ["profile"], None)
