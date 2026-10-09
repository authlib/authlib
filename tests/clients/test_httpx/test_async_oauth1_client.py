from unittest import mock
from urllib.parse import parse_qsl

import pytest
from httpx2 import ASGITransport

from authlib.integrations.httpx_client import SIGNATURE_TYPE_BODY
from authlib.integrations.httpx_client import SIGNATURE_TYPE_QUERY
from authlib.integrations.httpx_client import AsyncOAuth1Client
from authlib.integrations.httpx_client import OAuthError
from authlib.oauth1.rfc5849.signature import verify_hmac_sha1
from authlib.oauth1.rfc5849.wrapper import OAuth1Request

from ..asgi_helper import AsyncMockDispatch

oauth_url = "https://provider.test/oauth"


async def assert_valid_signature(request, client_secret="secret", token_secret=None):
    body = await request.body()
    oauth_request = OAuth1Request(
        request.method,
        str(request.url),
        body=body.decode() or None,
        headers=request.headers,
    )
    oauth_request.client = mock.Mock(get_client_secret=lambda: client_secret)
    oauth_request.credential = mock.Mock(get_oauth_token_secret=lambda: token_secret)
    assert verify_hmac_sha1(oauth_request)


@pytest.mark.asyncio
async def test_fetch_request_token_via_header():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    async def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert 'oauth_consumer_key="id"' in auth_header
        assert "oauth_signature=" in auth_header

        params = auth_header[len("OAuth ") :].split(", ")
        keys = [param.split("=")[0] for param in params]
        assert len(keys) == len(set(keys))
        await assert_valid_signature(request)

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
        oauth_keys = [
            key for key, _ in parse_qsl(content.decode()) if key.startswith("oauth_")
        ]
        assert len(oauth_keys) == len(set(oauth_keys))
        await assert_valid_signature(request)

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
        oauth_keys = [
            key
            for key, _ in request.query_params.multi_items()
            if key.startswith("oauth_")
        ]
        assert len(oauth_keys) == len(set(oauth_keys))
        await assert_valid_signature(request)

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
        response = await client.get("https://resource.test/")

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
        response = await client.post("https://resource.test/")

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
        response = await client.get("https://resource.test/")

    assert response.content == b"hello"
    request = response.request
    auth_header = request.headers.get("authorization")
    assert auth_header is None

    url = str(request.url)
    assert "oauth_token=foo" in url
    assert "oauth_consumer_key=id" in url
    assert "oauth_signature=" in url
