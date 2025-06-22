import time
from copy import deepcopy
from unittest import mock

import pytest
from httpx import WSGITransport

from authlib.common.security import generate_token
from authlib.common.urls import url_encode
from authlib.integrations.httpx_client import OAuth2Client
from authlib.integrations.httpx_client import OAuthError

from ..wsgi_helper import MockDispatch

default_token = {
    "token_type": "Bearer",
    "access_token": "a",
    "refresh_token": "b",
    "expires_in": "3600",
    "expires_at": int(time.time()) + 3600,
}


def assert_token_in_header(request):
    token = "Bearer " + default_token["access_token"]
    auth_header = request.headers.get("authorization")
    assert auth_header == token


def assert_token_in_body(request):
    content = request.data
    content = content.decode()
    assert content == "access_token={}".format(default_token["access_token"])


def assert_token_in_uri(request):
    assert default_token["access_token"] in str(request.url)


@pytest.mark.parametrize(
    "assert_func, token_placement",
    [
        (assert_token_in_header, "header"),
        (assert_token_in_body, "body"),
        (assert_token_in_uri, "uri"),
    ],
)
def test_add_token_get_request(assert_func, token_placement):
    transport = WSGITransport(MockDispatch({"a": "a"}, assert_func=assert_func))
    with OAuth2Client(
        "foo", token=default_token, token_placement=token_placement, transport=transport
    ) as client:
        resp = client.get("https://i.b")

    data = resp.json()
    assert data["a"] == "a"


@pytest.mark.parametrize(
    "assert_func, token_placement",
    [
        (assert_token_in_header, "header"),
        (assert_token_in_body, "body"),
        (assert_token_in_uri, "uri"),
    ],
)
def test_add_token_to_streaming_request(assert_func, token_placement):
    transport = WSGITransport(MockDispatch({"a": "a"}, assert_func=assert_func))
    with OAuth2Client(
        "foo", token=default_token, token_placement=token_placement, transport=transport
    ) as client:
        with client.stream("GET", "https://i.b") as stream:
            stream.read()
            data = stream.json()
    assert data["a"] == "a"


def test_create_authorization_url():
    url = "https://example.com/authorize?foo=bar"

    sess = OAuth2Client(client_id="foo")
    auth_url, state = sess.create_authorization_url(url)
    assert state in auth_url
    assert "client_id=foo" in auth_url
    assert "response_type=code" in auth_url

    sess = OAuth2Client(client_id="foo", prompt="none")
    auth_url, state = sess.create_authorization_url(
        url, state="foo", redirect_uri="https://i.b", scope="profile"
    )
    assert state == "foo"
    assert "i.b" in auth_url
    assert "profile" in auth_url
    assert "prompt=none" in auth_url


def test_code_challenge():
    sess = OAuth2Client("foo", code_challenge_method="S256")

    url = "https://example.com/authorize"
    auth_url, _ = sess.create_authorization_url(url, code_verifier=generate_token(48))
    assert "code_challenge=" in auth_url
    assert "code_challenge_method=S256" in auth_url


def test_token_from_fragment():
    sess = OAuth2Client("foo")
    response_url = "https://i.b/callback#" + url_encode(default_token.items())
    assert sess.token_from_fragment(response_url) == default_token
    token = sess.fetch_token(authorization_response=response_url)
    assert token == default_token


def test_fetch_token_post():
    url = "https://example.com/token"

    def assert_func(request):
        content = request.form
        assert content.get("code") == "v"
        assert content.get("client_id") == "foo"
        assert content.get("grant_type") == "authorization_code"

    transport = WSGITransport(MockDispatch(default_token, assert_func=assert_func))
    with OAuth2Client("foo", transport=transport) as client:
        token = client.fetch_token(url, authorization_response="https://i.b/?code=v")
        assert token == default_token

    with OAuth2Client(
        "foo", token_endpoint_auth_method="none", transport=transport
    ) as client:
        token = client.fetch_token(url, code="v")
        assert token == default_token

    transport = WSGITransport(MockDispatch({"error": "invalid_request"}))
    with OAuth2Client("foo", transport=transport) as client:
        with pytest.raises(OAuthError):
            client.fetch_token(url)


def test_fetch_token_get():
    url = "https://example.com/token"

    def assert_func(request):
        url = str(request.url)
        assert "code=v" in url
        assert "client_id=" in url
        assert "grant_type=authorization_code" in url

    transport = WSGITransport(MockDispatch(default_token, assert_func=assert_func))
    with OAuth2Client("foo", transport=transport) as client:
        authorization_response = "https://i.b/?code=v"
        token = client.fetch_token(
            url, authorization_response=authorization_response, method="GET"
        )
        assert token == default_token

    with OAuth2Client(
        "foo", token_endpoint_auth_method="none", transport=transport
    ) as client:
        token = client.fetch_token(url, code="v", method="GET")
        assert token == default_token

        token = client.fetch_token(url + "?q=a", code="v", method="GET")
        assert token == default_token


def test_token_auth_method_client_secret_post():
    url = "https://example.com/token"

    def assert_func(request):
        content = request.form
        assert content.get("code") == "v"
        assert content.get("client_id") == "foo"
        assert content.get("client_secret") == "bar"
        assert content.get("grant_type") == "authorization_code"

    transport = WSGITransport(MockDispatch(default_token, assert_func=assert_func))
    with OAuth2Client(
        "foo",
        "bar",
        token_endpoint_auth_method="client_secret_post",
        transport=transport,
    ) as client:
        token = client.fetch_token(url, code="v")

    assert token == default_token


def test_access_token_response_hook():
    url = "https://example.com/token"

    def _access_token_response_hook(resp):
        assert resp.json() == default_token
        return resp

    access_token_response_hook = mock.Mock(side_effect=_access_token_response_hook)
    transport = WSGITransport(MockDispatch(default_token))
    with OAuth2Client("foo", token=default_token, transport=transport) as sess:
        sess.register_compliance_hook(
            "access_token_response", access_token_response_hook
        )
        assert sess.fetch_token(url) == default_token
        assert access_token_response_hook.called is True


def test_password_grant_type():
    url = "https://example.com/token"

    def assert_func(request):
        content = request.form
        assert content.get("username") == "v"
        assert content.get("scope") == "profile"
        assert content.get("grant_type") == "password"

    transport = WSGITransport(MockDispatch(default_token, assert_func=assert_func))
    with OAuth2Client("foo", scope="profile", transport=transport) as sess:
        token = sess.fetch_token(url, username="v", password="v")
        assert token == default_token

        token = sess.fetch_token(url, username="v", password="v", grant_type="password")
        assert token == default_token


def test_client_credentials_type():
    url = "https://example.com/token"

    def assert_func(request):
        content = request.form
        assert content.get("scope") == "profile"
        assert content.get("grant_type") == "client_credentials"

    transport = WSGITransport(MockDispatch(default_token, assert_func=assert_func))
    with OAuth2Client("foo", scope="profile", transport=transport) as sess:
        token = sess.fetch_token(url)
        assert token == default_token

        token = sess.fetch_token(url, grant_type="client_credentials")
        assert token == default_token


def test_cleans_previous_token_before_fetching_new_one():
    now = int(time.time())
    new_token = deepcopy(default_token)
    past = now - 7200
    default_token["expires_at"] = past
    new_token["expires_at"] = now + 3600
    url = "https://example.com/token"

    transport = WSGITransport(MockDispatch(new_token))
    with mock.patch("time.time", lambda: now):
        with OAuth2Client("foo", token=default_token, transport=transport) as sess:
            assert sess.fetch_token(url) == new_token


def test_token_status():
    token = dict(access_token="a", token_type="bearer", expires_at=100)
    sess = OAuth2Client("foo", token=token)
    assert sess.token.is_expired() is True


def test_auto_refresh_token():
    def _update_token(token, refresh_token=None, access_token=None):
        assert refresh_token == "b"
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(
        access_token="a", refresh_token="b", token_type="bearer", expires_at=100
    )

    transport = WSGITransport(MockDispatch(default_token))
    with OAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        transport=transport,
    ) as sess:
        sess.get("https://i.b/user")
        assert update_token.called is True

    old_token = dict(access_token="a", token_type="bearer", expires_at=100)
    with OAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        transport=transport,
    ) as sess:
        with pytest.raises(OAuthError):
            sess.get("https://i.b/user")


def test_auto_refresh_token2():
    def _update_token(token, refresh_token=None, access_token=None):
        assert access_token == "a"
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(access_token="a", token_type="bearer", expires_at=100)

    transport = WSGITransport(MockDispatch(default_token))

    with OAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        client.get("https://i.b/user")
        assert update_token.called is False

    with OAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        client.get("https://i.b/user")
        assert update_token.called is True


def test_auto_refresh_token3():
    def _update_token(token, refresh_token=None, access_token=None):
        assert access_token == "a"
        assert token == default_token

    update_token = mock.Mock(side_effect=_update_token)

    old_token = dict(access_token="a", token_type="bearer", expires_at=100)

    transport = WSGITransport(MockDispatch(default_token))

    with OAuth2Client(
        "foo",
        token=old_token,
        token_endpoint="https://i.b/token",
        update_token=update_token,
        grant_type="client_credentials",
        transport=transport,
    ) as client:
        client.post("https://i.b/user", json={"foo": "bar"})
        assert update_token.called is True


def test_revoke_token():
    answer = {"status": "ok"}
    transport = WSGITransport(MockDispatch(answer))

    with OAuth2Client("a", transport=transport) as sess:
        resp = sess.revoke_token("https://i.b/token", "hi")
        assert resp.json() == answer

        resp = sess.revoke_token(
            "https://i.b/token", "hi", token_type_hint="access_token"
        )
        assert resp.json() == answer


def test_request_without_token():
    transport = WSGITransport(MockDispatch())
    with OAuth2Client("a", transport=transport) as client:
        with pytest.raises(OAuthError):
            client.get("https://i.b/token")
