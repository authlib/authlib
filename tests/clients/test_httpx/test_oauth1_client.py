import pytest
from httpx import WSGITransport

from authlib.integrations.httpx_client import SIGNATURE_TYPE_BODY
from authlib.integrations.httpx_client import SIGNATURE_TYPE_QUERY
from authlib.integrations.httpx_client import OAuth1Client
from authlib.integrations.httpx_client import OAuthError

from ..wsgi_helper import MockDispatch

oauth_url = "https://example.com/oauth"


def test_fetch_request_token_via_header():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert 'oauth_consumer_key="id"' in auth_header
        assert "oauth_signature=" in auth_header

    transport = WSGITransport(MockDispatch(request_token, assert_func=assert_func))
    with OAuth1Client("id", "secret", transport=transport) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


def test_fetch_request_token_via_body():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert auth_header is None

        content = request.form
        assert content.get("oauth_consumer_key") == "id"
        assert "oauth_signature" in content

    transport = WSGITransport(MockDispatch(request_token, assert_func=assert_func))

    with OAuth1Client(
        "id",
        "secret",
        signature_type=SIGNATURE_TYPE_BODY,
        transport=transport,
    ) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


def test_fetch_request_token_via_query():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert auth_header is None

        url = str(request.url)
        assert "oauth_consumer_key=id" in url
        assert "&oauth_signature=" in url

    transport = WSGITransport(MockDispatch(request_token, assert_func=assert_func))

    with OAuth1Client(
        "id",
        "secret",
        signature_type=SIGNATURE_TYPE_QUERY,
        transport=transport,
    ) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


def test_fetch_access_token():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert 'oauth_verifier="d"' in auth_header
        assert 'oauth_token="foo"' in auth_header
        assert 'oauth_consumer_key="id"' in auth_header
        assert "oauth_signature=" in auth_header

    transport = WSGITransport(MockDispatch(request_token, assert_func=assert_func))
    with OAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        transport=transport,
    ) as client:
        with pytest.raises(OAuthError):
            client.fetch_access_token(oauth_url)

        response = client.fetch_access_token(oauth_url, verifier="d")

    assert response == request_token


def test_get_via_header():
    transport = WSGITransport(MockDispatch(b"hello"))
    with OAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        transport=transport,
    ) as client:
        response = client.get("https://example.com/")

    assert response.content == b"hello"
    request = response.request
    auth_header = request.headers.get("authorization")
    assert 'oauth_token="foo"' in auth_header
    assert 'oauth_consumer_key="id"' in auth_header
    assert "oauth_signature=" in auth_header


def test_get_via_body():
    def assert_func(request):
        content = request.form
        assert content.get("oauth_token") == "foo"
        assert content.get("oauth_consumer_key") == "id"
        assert "oauth_signature" in content

    transport = WSGITransport(MockDispatch(b"hello", assert_func=assert_func))
    with OAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        signature_type=SIGNATURE_TYPE_BODY,
        transport=transport,
    ) as client:
        response = client.post("https://example.com/")

    assert response.content == b"hello"

    request = response.request
    auth_header = request.headers.get("authorization")
    assert auth_header is None


def test_get_via_query():
    transport = WSGITransport(MockDispatch(b"hello"))
    with OAuth1Client(
        "id",
        "secret",
        token="foo",
        token_secret="bar",
        signature_type=SIGNATURE_TYPE_QUERY,
        transport=transport,
    ) as client:
        response = client.get("https://example.com/")

    assert response.content == b"hello"
    request = response.request
    auth_header = request.headers.get("authorization")
    assert auth_header is None

    url = str(request.url)
    assert "oauth_token=foo" in url
    assert "oauth_consumer_key=id" in url
    assert "oauth_signature=" in url
