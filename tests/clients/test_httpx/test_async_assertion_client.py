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
        if str(request.url) == "https://i.b/token":
            assert b"assertion=" in content

    async with AsyncAssertionClient(
        "https://i.b/token",
        grant_type=AsyncAssertionClient.JWT_BEARER_GRANT_TYPE,
        issuer="foo",
        subject="foo",
        audience="foo",
        alg="HS256",
        key="secret",
        transport=ASGITransport(AsyncMockDispatch(default_token, assert_func=verifier)),
    ) as client:
        await client.get("https://i.b")

    # trigger more case
    now = int(time.time())
    async with AsyncAssertionClient(
        "https://i.b/token",
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
        await client.get("https://i.b")
        await client.get("https://i.b")


@pytest.mark.asyncio
async def test_without_alg():
    async with AsyncAssertionClient(
        "https://i.b/token",
        issuer="foo",
        subject="foo",
        audience="foo",
        key="secret",
        transport=ASGITransport(AsyncMockDispatch()),
    ) as client:
        with pytest.raises(ValueError):
            await client.get("https://i.b")
