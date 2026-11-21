import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authlib.integrations.fastapi_oauth2.errors import OAuth2HTTPException
from authlib.integrations.fastapi_oauth2.errors import oauth2_exception_handler
from authlib.integrations.fastapi_oauth2.errors import raise_http_exception


@pytest.fixture
def app():
    app = FastAPI()
    app.add_exception_handler(
        OAuth2HTTPException,
        oauth2_exception_handler,
    )

    @app.get("/test")
    def test_endpoint():
        raise_http_exception(
            400,
            '{"error": "invalid_request"}',
            {"X-Test": "test-header"},
        )

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestOAuth2HTTPException:
    def test_initialization(self):
        body = '{"error": "invalid_client"}'
        headers = {"WWW-Authenticate": "Basic"}

        exc = OAuth2HTTPException(
            status_code=401,
            body=body,
            headers=headers,
        )

        assert exc.status_code == 401
        assert exc.body == body
        assert exc.detail == body
        assert exc.headers == headers

    def test_initialization_without_headers(self):
        exc = OAuth2HTTPException(
            status_code=400,
            body='{"error": "invalid_request"}',
        )

        assert exc.status_code == 400
        assert exc.body == '{"error": "invalid_request"}'
        assert exc.headers is None


class TestRaiseHTTPException:
    def test_raises_oauth2_http_exception(self):
        body = '{"error": "invalid_grant"}'
        headers = {"X-Test": "value"}

        with pytest.raises(OAuth2HTTPException) as exc_info:
            raise_http_exception(400, body, headers)

        exc = exc_info.value

        assert exc.status_code == 400
        assert exc.body == body
        assert exc.headers == headers


class TestOAuth2ExceptionHandler:
    def test_returns_response(self):
        body = '{"error": "invalid_client"}'
        exc = OAuth2HTTPException(401, body)

        response = oauth2_exception_handler(None, exc)

        assert response.status_code == 401
        assert response.body == body.encode()
        assert response.media_type == "application/json"

    def test_preserves_headers(self):
        headers = {
            "WWW-Authenticate": "Basic",
            "Cache-Control": "no-store",
        }
        exc = OAuth2HTTPException(
            401,
            '{"error": "invalid_client"}',
            headers,
        )

        response = oauth2_exception_handler(None, exc)

        assert response.headers["www-authenticate"] == "Basic"
        assert response.headers["cache-control"] == "no-store"

    def test_preserves_empty_body(self):
        exc = OAuth2HTTPException(400, "")

        response = oauth2_exception_handler(None, exc)

        assert response.body == b""
        assert response.status_code == 400


class TestOAuth2ExceptionIntegration:
    def test_endpoint_returns_oauth2_error(self, client):
        response = client.get("/test")

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert response.headers["x-test"] == "test-header"
        assert response.headers["content-type"] == "application/json"
