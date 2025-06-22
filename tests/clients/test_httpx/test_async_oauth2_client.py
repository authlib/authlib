import asyncio
import time
from copy import deepcopy
from unittest import mock

import pytest
from httpx import ASGITransport
from httpx import AsyncClient

from authlib.common.security import generate_token
from authlib.common.urls import url_encode
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuthError

from ..asgi_helper import AsyncMockDispatch

default_token = {
    "token_type": "Bearer",
    "access_token": "a",
    "refresh_token": "b",
    "expires_in": "3600",
    "expires_at": int(time.time()) + 3600,
}


@pytest.mark.asyncio
async def assert_token_in_header(request):
    token = "Bearer " + default_token["access_token"]
    auth_header = request.headers.get("authorization")
    assert auth_header == token


@pytest.mark.asyncio
async def assert_token_in_body(request):
    content = await request.body()
    assert default_token["access_token"] in content.decode()


@pytest.mark.asyncio
async def assert_token_in_uri(request):
    assert default_token["access_token"] in str(request.url)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "assert_func, token_placement",
    [
        (assert_token_in_header, "header"),
        (assert_token_in_body, "body"),
        (assert_token_in_uri, "uri"),
    ],
)
async def test_add_token_get_request(assert_func, token_placement):
    transport = ASGITransport(AsyncMockDispatch({"a": "a"}, assert_func=assert_func))
    async with AsyncOAuth2Client(
        "foo", token=default_token, token_placement=token_placement, transport=transport
    ) as client:
        resp = await client.get("https://i.b")

    data = resp.json()
    assert data["a"] == "a"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "assert_func, token_placement",
    [
        (assert_token_in_header, "header"),
        (assert_token_in_body, "body"),
        (assert_token_in_uri, "uri"),
    ],
)
async def test_add_token_to_streaming_request(assert_func, token_placement):
    transport = ASGITransport(AsyncMockDispatch({"a": "a"}, assert_func=assert_func))
    async with AsyncOAuth2Client(
        "foo", token=default_token, token_placement=token_placement, transport=transport
    ) as client:
        async with client.stream("GET", "https://i.b") as stream:
            await stream.aread()
            data = stream.json()

    assert data["a"] == "a"


@pytest.mark.parametrize(
    "client",
    [
        AsyncOAuth2Client(
            "foo",
            token=default_token,
            token_placement="header",
            transport=ASGITransport(
                AsyncMockDispatch({"a": "a"}, assert_func=assert_token_in_header)
            ),
        ),
        AsyncClient(transport=ASGITransport(AsyncMockDispatch({"a": "a"}))),
    ],
)
async def test_httpx_client_stream_match(client):
    async with client as client_entered:
        async with client_entered.stream("GET", "https://i.b") as stream:
            assert stream.status_code == 200


def test_create_authorization_url():
    url = "https://example.com/authorize?foo=bar"

    sess = AsyncOAuth2Client(client_id="foo")
    auth_url, state = sess.create_authorization_url(url)
    assert state in auth_url
    assert "client_id=foo" in auth_url
    assert "response_type=code" in auth_url

    sess = AsyncOAuth2Client(client_id="foo", prompt="none")
    auth_url, state = sess.create_authorization_url(
        url, state="foo", redirect_uri="https://i.b", scope="profile"
    )
    assert state == "foo"
    assert "i.b" in auth_url
    assert "profile" in auth_url
    assert "prompt=none" in auth_url


def test_code_challenge():
    sess = AsyncOAuth2Client("foo", code_challenge_method="S256")

    url = "https://example.com/authorize"
    auth_url, _ = sess.create_authorization_url(url, code_verifier=generate_token(48))
    assert "code_challenge=" in auth_url
    assert "code_challenge_method=S256" in auth_url


def test_token_from_fragment():
    sess = AsyncOAuth2Client("foo")
    response_url = "https://i.b/callback#" + url_encode(default_token.items())
    assert sess.token_from_fragment(response_url) == default_token
    token = sess.fetch_token(authorization_response=response_url)
    assert token == default_token


@pytest.mark.asyncio
async def test_fetch_token_post():
    url = "https://example.com/token"

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert "code=v" in content
        assert "client_id=" in content
        assert "grant_type=authorization_code" in content

    transport = ASGITransport(AsyncMockDispatch(default_token, assert_func=assert_func))
    async with AsyncOAuth2Client("foo", transport=transport) as client:
        token = await client.fetch_token(
            url, authorization_response="https://i.b/?code=v"
        )
        assert token == default_token

    async with AsyncOAuth2Client(
        "foo", token_endpoint_auth_method="none", transport=transport
    ) as client:
        token = await client.fetch_token(url, code="v")
        assert token == default_token

    transport = ASGITransport(AsyncMockDispatch({"error": "invalid_request"}))
    async with AsyncOAuth2Client("foo", transport=transport) as client:
        with pytest.raises(OAuthError):
            await client.fetch_token(url)


@pytest.mark.asyncio
async def test_fetch_token_get():
    url = "https://example.com/token"

    async def assert_func(request):
        url = str(request.url)
        assert "code=v" in url
        assert "client_id=" in url
        assert "grant_type=authorization_code" in url

    transport = ASGITransport(AsyncMockDispatch(default_token, assert_func=assert_func))
    async with AsyncOAuth2Client("foo", transport=transport) as client:
        authorization_response = "https://i.b/?code=v"
        token = await client.fetch_token(
            url, authorization_response=authorization_response, method="GET"
        )
        assert token == default_token

    async with AsyncOAuth2Client(
        "foo", token_endpoint_auth_method="none", transport=transport
    ) as client:
        token = await client.fetch_token(url, code="v", method="GET")
        assert token == default_token

        token = await client.fetch_token(url + "?q=a", code="v", method="GET")
        assert token == default_token


@pytest.mark.asyncio
async def test_token_auth_method_client_secret_post():
    url = "https://example.com/token"

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert "code=v" in content
        assert "client_id=" in content
        assert "client_secret=bar" in content
        assert "grant_type=authorization_code" in content

    transport = ASGITransport(AsyncMockDispatch(default_token, assert_func=assert_func))
    async with AsyncOAuth2Client(
        "foo",
        "bar",
        token_endpoint_auth_method="client_secret_post",
        transport=transport,
    ) as client:
        token = await client.fetch_token(url, code="v")

    assert token == default_token


@pytest.mark.asyncio
async def test_access_token_response_hook():
    url = "https://example.com/token"

    def _access_token_response_hook(resp):
        assert resp.json() == default_token
        return resp

    access_token_response_hook = mock.Mock(side_effect=_access_token_response_hook)
    transport = ASGITransport(AsyncMockDispatch(default_token))
    async with AsyncOAuth2Client(
        "foo", token=default_token, transport=transport
    ) as sess:
        sess.register_compliance_hook(
            "access_token_response", access_token_response_hook
        )
        assert await sess.fetch_token(url) == default_token
        assert access_token_response_hook.called is True


@pytest.mark.asyncio
async def test_password_grant_type():
    url = "https://example.com/token"

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert "username=v" in content
        assert "scope=profile" in content
        assert "grant_type=password" in content

    transport = ASGITransport(AsyncMockDispatch(default_token, assert_func=assert_func))
    async with AsyncOAuth2Client("foo", scope="profile", transport=transport) as sess:
        token = await sess.fetch_token(url, username="v", password="v")
        assert token == default_token

        token = await sess.fetch_token(
            url, username="v", password="v", grant_type="password"
        )
        assert token == default_token


@pytest.mark.asyncio
async def test_client_credentials_type():
    url = "https://example.com/token"

    async def assert_func(request):
        content = await request.body()
        content = content.decode()
        assert "scope=profile" in content
        assert "grant_type=client_credentials" in content

    transport = ASGITransport(AsyncMockDispatch(default_token, assert_func=assert_func))
    async with AsyncOAuth2Client("foo", scope="profile", transport=transport) as sess:
        token = await sess.fetch_token(url)
        assert token == default_token

        token = await sess.fetch_token(url, grant_type="client_credentials")
        assert token == default_token


@pytest.mark.asyncio
async def test_cleans_previous_token_before_fetching_new_one():
    now = int(time.time())
    new_token = deepcopy(default_token)
    past = now - 7200
    default_token["expires_at"] = past
    new_token["expires_at"] = now + 3600
    url = "https://example.com/token"

    transport = ASGITransport(AsyncMockDispatch(new_token))
    with mock.patch("time.time", lambda: now):
        async with AsyncOAuth2Client(
            "foo", token=default_token, transport=transport
        ) as sess:
            assert await sess.fetch_token(url) == new_token


def test_token_status():
    token = dict(access_token="a", token_type="bearer", expires_at=100)
    sess = AsyncOAuth2Client("foo", token=token)
    assert sess.token.is_expired() is True


@pytest.mark.asyncio
async def test_auto_refresh_token():
    async def _update_token(token, refresh_token=None, access_token=None):
        assert refresh_token == "b"
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(
        access_token="a", refresh_token="b", token_type="bearer", expires_at=100
    )

    transport = ASGITransport(AsyncMockDispatch(default_token))
    async with AsyncOAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        transport=transport,
    ) as sess:
        await sess.get("https://i.b/user")
        assert update_token.called is True

    old_token = dict(access_token="a", token_type="bearer", expires_at=100)
    async with AsyncOAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        transport=transport,
    ) as sess:
        with pytest.raises(OAuthError):
            await sess.get("https://i.b/user")


@pytest.mark.asyncio
async def test_auto_refresh_token2():
    async def _update_token(token, refresh_token=None, access_token=None):
        assert access_token == "a"
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(access_token="a", token_type="bearer", expires_at=100)

    transport = ASGITransport(AsyncMockDispatch(default_token))

    async with AsyncOAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        await client.get("https://i.b/user")
        assert update_token.called is False

    async with AsyncOAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        await client.get("https://i.b/user")
        assert update_token.called is True


@pytest.mark.asyncio
async def test_auto_refresh_token3():
    async def _update_token(token, refresh_token=None, access_token=None):
        assert access_token == "a"
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(access_token="a", token_type="bearer", expires_at=100)

    transport = ASGITransport(AsyncMockDispatch(default_token))

    async with AsyncOAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        await client.post("https://i.b/user", json={"foo": "bar"})
        assert update_token.called is True


@pytest.mark.asyncio
async def test_auto_refresh_token4():
    async def _update_token(token, refresh_token=None, access_token=None):
        # This test only makes sense if the expired token is refreshed
        token["expires_at"] = int(time.time()) + 3600
        # artificial sleep to force other coroutines to wake
        await asyncio.sleep(0.1)

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(access_token="old", token_type="bearer", expires_at=100)

    transport = ASGITransport(AsyncMockDispatch(default_token))

    async with AsyncOAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        coroutines = [client.get("https://i.b/user") for x in range(10)]
        await asyncio.gather(*coroutines)
        update_token.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_token():
    answer = {"status": "ok"}
    transport = ASGITransport(AsyncMockDispatch(answer))

    async with AsyncOAuth2Client("a", transport=transport) as sess:
        resp = await sess.revoke_token("https://i.b/token", "hi")
        assert resp.json() == answer

        resp = await sess.revoke_token(
            "https://i.b/token", "hi", token_type_hint="access_token"
        )
        assert resp.json() == answer


@pytest.mark.asyncio
async def test_request_without_token():
    transport = ASGITransport(AsyncMockDispatch())
    async with AsyncOAuth2Client("a", transport=transport) as client:
        with pytest.raises(OAuthError):
            await client.get("https://i.b/token")
