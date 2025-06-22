import pytest
from httpx import ASGITransport

from authlib.integrations.httpx_client import SIGNATURE_TYPE_BODY
from authlib.integrations.httpx_client import SIGNATURE_TYPE_QUERY
from authlib.integrations.httpx_client import AsyncOAuth1Client
from authlib.integrations.httpx_client import OAuthError

from ..asgi_helper import AsyncMockDispatch

oauth_url = "https://example.com/oauth"


@pytest.mark.asyncio
async def test_fetch_request_token_via_header():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    async def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert 'oauth_consumer_key="id"' in auth_header
        assert "oauth_signature=" in auth_header

    transport = ASGITransport(AsyncMockDispatch(request_token, assert_func=assert_func))
    async with AsyncOAuth1Client("id", "secret", transport=transport) as client:
        response = await client.fetch_request_token(oauth_url)

    assert response == request_token


@pytest.mark.asyncio
async def test_fetch_request_token_via_body():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    async def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert auth_header is None

        content = await request.body()
        assert b"oauth_consumer_key=id" in content
        assert b"&oauth_signature=" in content

    transport = ASGITransport(AsyncMockDispatch(request_token, assert_func=assert_func))

    async with AsyncOAuth1Client(
        "id",
        "secret",
        signature_type=SIGNATURE_TYPE_BODY,
        transport=transport,
    ) as client:
        response = await client.fetch_request_token(oauth_url)

    assert response == request_token


@pytest.mark.asyncio
async def test_fetch_request_token_via_query():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    async def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert auth_header is None

        url = str(request.url)
        assert "oauth_consumer_key=id" in url
        assert "&oauth_signature=" in url

    transport = ASGITransport(AsyncMockDispatch(request_token, assert_func=assert_func))

    async with AsyncOAuth1Client(
        "id",
        "secret",
        signature_type=SIGNATURE_TYPE_QUERY,
        transport=transport,
    ) as client:
        response = await client.fetch_request_token(oauth_url)

    assert response == request_token


@pytest.mark.asyncio
async def test_fetch_access_token():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    async def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert 'oauth_verifier="d"' in auth_header
        assert 'oauth_token="foo"' in auth_header
        assert 'oauth_consumer_key="id"' in auth_header
        assert "oauth_signature=" in auth_header

    transport = ASGITransport(AsyncMockDispatch(request_token, assert_func=assert_func))
    async with AsyncOAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        transport=transport,
    ) as client:
        with pytest.raises(OAuthError):
            await client.fetch_access_token(oauth_url)

        response = await client.fetch_access_token(oauth_url, verifier="d")

    assert response == request_token


@pytest.mark.asyncio
async def test_get_via_header():
    transport = ASGITransport(AsyncMockDispatch(b"hello"))
    async with AsyncOAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        transport=transport,
    ) as client:
        response = await client.get("https://example.com/")

    assert response.content == b"hello"
    request = response.request
    auth_header = request.headers.get("authorization")
    assert 'oauth_token="foo"' in auth_header
    assert 'oauth_consumer_key="id"' in auth_header
    assert "oauth_signature=" in auth_header


@pytest.mark.asyncio
async def test_get_via_body():
    async def assert_func(request):
        content = await request.body()
        assert b"oauth_token=foo" in content
        assert b"oauth_consumer_key=id" in content
        assert b"oauth_signature=" in content

    transport = ASGITransport(AsyncMockDispatch(b"hello", assert_func=assert_func))
    async with AsyncOAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        signature_type=SIGNATURE_TYPE_BODY,
        transport=transport,
    ) as client:
        response = await client.post("https://example.com/")

    assert response.content == b"hello"

    request = response.request
    auth_header = request.headers.get("authorization")
    assert auth_header is None


@pytest.mark.asyncio
async def test_get_via_query():
    transport = ASGITransport(AsyncMockDispatch(b"hello"))
    async with AsyncOAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        signature_type=SIGNATURE_TYPE_QUERY,
        transport=transport,
    ) as client:
        response = await client.get("https://example.com/")

    assert response.content == b"hello"
    request = response.request
    auth_header = request.headers.get("authorization")
    assert auth_header is None

    url = str(request.url)
    assert "oauth_token=foo" in url
    assert "oauth_consumer_key=id" in url
    assert "oauth_signature=" in url
