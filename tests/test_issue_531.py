import httpx2 as httpx
import pytest

from authlib.integrations.base_client import MissingTokenError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuth2Client


def test_automatic_initial_token_fetch():
    """The client should fetch an initial token automatically."""

    requests_received = []

    def mock_handler(request):
        requests_received.append(str(request.url))

        # Simulate OAuth server issuing an access token
        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "test-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        # Simulate a protected API endpoint
        if request.url.path == "/api/data":
            authorization = request.headers.get("Authorization")

            if authorization == "Bearer test-access-token":
                return httpx.Response(
                    200,
                    json={"message": "Success"},
                )

            return httpx.Response(
                401,
                json={"error": "Unauthorized"},
            )

        return httpx.Response(404)

    # Mock HTTP requests without using the internet
    transport = httpx.MockTransport(mock_handler)

    with OAuth2Client(
        client_id="test-client",
        client_secret="test-secret",
        token_endpoint="https://example.com/oauth/token",
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        response = client.get("https://example.com/api/data")

        assert response.status_code == 200
        assert response.json()["message"] == "Success"

        # Verify the token was requested first
        assert requests_received == [
            "https://example.com/oauth/token",
            "https://example.com/api/data",
        ]


def test_existing_valid_token_is_reused():
    """An existing valid token should not be fetched again."""

    requests_received = []

    def mock_handler(request):
        requests_received.append(str(request.url))

        if request.url.path == "/api/data":
            auth_header = request.headers.get("Authorization")

            if auth_header == "Bearer existing-token":
                return httpx.Response(
                    200,
                    json={"message": "Success"},
                )

            return httpx.Response(401)

        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)

    with OAuth2Client(
        client_id="test-client",
        client_secret="test-secret",
        token_endpoint="https://example.com/oauth/token",
        grant_type="client_credentials",
        token={
            "access_token": "existing-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
        transport=transport,
    ) as client:
        response = client.get("https://example.com/api/data")

        assert response.status_code == 200
        assert requests_received == ["https://example.com/api/data"]


def test_missing_token_configuration():
    """A client without token configuration should raise MissingTokenError."""

    requests_received = []

    def mock_handler(request):
        requests_received.append(str(request.url))
        return httpx.Response(200)

    transport = httpx.MockTransport(mock_handler)

    with OAuth2Client(
        client_id="test-client",
        client_secret="test-secret",
        transport=transport,
    ) as client:
        with pytest.raises(MissingTokenError):
            client.get("https://example.com/api/data")

    # The request should never reach the API server.
    assert requests_received == []


def test_stream_automatically_fetches_initial_token():
    """Streaming requests should fetch an initial token."""

    requests_received = []

    def mock_handler(request):
        requests_received.append(str(request.url))

        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "stream-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        if request.url.path == "/api/data":
            if request.headers.get("Authorization") == "Bearer stream-token":
                return httpx.Response(
                    200,
                    json={"message": "Stream success"},
                )

            return httpx.Response(401)

        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)

    with OAuth2Client(
        client_id="test-client",
        client_secret="test-secret",
        token_endpoint="https://example.com/oauth/token",
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        with client.stream("GET", "https://example.com/api/data") as response:
            assert response.status_code == 200
            assert response.json()["message"] == "Stream success"

    assert requests_received == [
        "https://example.com/oauth/token",
        "https://example.com/api/data",
    ]


@pytest.mark.asyncio
async def test_async_automatic_initial_token_fetch():
    """Async client should fetch an initial token."""

    requests_received = []

    def mock_handler(request):
        requests_received.append(str(request.url))

        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "async-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        if request.url.path == "/api/data":
            auth_header = request.headers.get("Authorization")

            if auth_header == "Bearer async-token":
                return httpx.Response(
                    200,
                    json={"message": "Async success"},
                )

            return httpx.Response(401)

        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)

    async with AsyncOAuth2Client(
        client_id="test-client",
        client_secret="test-secret",
        token_endpoint="https://example.com/oauth/token",
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        response = await client.get("https://example.com/api/data")

        assert response.status_code == 200
        assert response.json()["message"] == "Async success"

    assert requests_received == [
        "https://example.com/oauth/token",
        "https://example.com/api/data",
    ]


@pytest.mark.asyncio
async def test_async_stream_automatically_fetches_initial_token():
    """Async streaming should fetch an initial access token."""

    requests_received = []

    def mock_handler(request):
        requests_received.append(str(request.url))

        if request.url.path == "/oauth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "async-stream-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        if request.url.path == "/api/data":
            auth_header = request.headers.get("Authorization")

            if auth_header == "Bearer async-stream-token":
                return httpx.Response(
                    200,
                    json={"message": "Async stream success"},
                )

            return httpx.Response(401)

        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)

    async with AsyncOAuth2Client(
        client_id="test-client",
        client_secret="test-secret",
        token_endpoint="https://example.com/oauth/token",
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        async with client.stream("GET", "https://example.com/api/data") as response:
            assert response.status_code == 200
            assert (await response.aread()) is not None

    assert requests_received == [
        "https://example.com/oauth/token",
        "https://example.com/api/data",
    ]
