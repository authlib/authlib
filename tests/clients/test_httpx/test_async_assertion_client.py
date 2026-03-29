import time

import pytest
from httpx import ASGITransport

from authlib.integrations.httpx_client import AsyncAssertionClient

from ..asgi_helper import AsyncMockDispatch

default_token = {
    "token_type": "Bearer",
    "access_token": "a",
    "refresh_token": "b",
    "expires_in": "3600",
    "expires_at": int(time.time()) + 3600,
}


@pytest.mark.asyncio
async def test_refresh_token():
    async def verifier(request):
        content = await request.body()
        if str(request.url) == "https://provider.test/token":
            assert b"assertion=" in content

    async with AsyncAssertionClient(
        "https://provider.test/token",
        grant_type=AsyncAssertionClient.JWT_BEARER_GRANT_TYPE,
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
        transport=ASGITransport(AsyncMockDispatch(default_token, assert_func=verifier)),
    ) as client:
        await client.get("https://provider.test")

    # trigger more case
    now = int(time.time())
    async with AsyncAssertionClient(
        "https://provider.test/token",
        issuer="foo",
        subject=None,
        audience="foo",
        issued_at=now,
        expires_at=now + 3600,
        header={"alg": "HS256"},
        key="secret",
        scope="email",
        claims={"test_mode": "true"},
        transport=ASGITransport(AsyncMockDispatch(default_token, assert_func=verifier)),
    ) as client:
        await client.get("https://provider.test")
        await client.get("https://provider.test")


@pytest.mark.asyncio
async def test_client_id():
    """client_id is included in the token request body when provided."""

    async def verifier(request):
        if str(request.url) == "https://provider.test/token":
            content = await request.body()
            assert b"assertion=" in content
            assert b"client_id=my-client" in content

    async with AsyncAssertionClient(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
        client_id="my-client",
        transport=ASGITransport(AsyncMockDispatch(default_token, assert_func=verifier)),
    ) as client:
        await client.get("https://provider.test")


@pytest.mark.asyncio
async def test_without_alg():
    async with AsyncAssertionClient(
        "https://provider.test/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        key="secret",
        transport=ASGITransport(AsyncMockDispatch()),
    ) as client:
        with pytest.raises(ValueError):
            await client.get("https://provider.test")
