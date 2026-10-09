
import httpx

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
            authorization = request.headers.get(
                "Authorization"
            )

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

        response = client.get(
            "https://example.com/api/data"
        )

        assert response.status_code == 200
        assert response.json()["message"] == "Success"

        # Verify the token was requested first
        assert requests_received == [
            "https://example.com/oauth/token",
            "https://example.com/api/data",
        ]
