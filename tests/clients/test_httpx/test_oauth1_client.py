from unittest import mock

import pytest
from httpx2 import WSGITransport

from authlib.integrations.httpx_client import SIGNATURE_TYPE_BODY
from authlib.integrations.httpx_client import SIGNATURE_TYPE_QUERY
from authlib.integrations.httpx_client import OAuth1Client
from authlib.integrations.httpx_client import OAuthError
from authlib.oauth1.rfc5849.signature import verify_hmac_sha1
from authlib.oauth1.rfc5849.wrapper import OAuth1Request

from ..wsgi_helper import MockDispatch

oauth_url = "https://provider.test/oauth"


def assert_valid_signature(request, client_secret="secret", token_secret=None):
    oauth_request = OAuth1Request(
        request.method,
        request.url,
        body=request.get_data(as_text=True),
        headers=request.headers,
    )
    oauth_request.client = mock.Mock(get_client_secret=lambda: client_secret)
    oauth_request.credential = mock.Mock(get_oauth_token_secret=lambda: token_secret)
    assert verify_hmac_sha1(oauth_request)


def test_fetch_request_token_via_header():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert 'oauth_consumer_key="id"' in auth_header
        assert "oauth_signature=" in auth_header

        params = auth_header[len("OAuth ") :].split(", ")
        keys = [param.split("=")[0] for param in params]
        assert len(keys) == len(set(keys))
        assert_valid_signature(request)

    transport = WSGITransport(MockDispatch(request_token, assert_func=assert_func))
    with OAuth1Client("id", "secret", transport=transport) as client:
        response = client.fetch_request_token(oauth_url)

    assert response == request_token


def test_fetch_request_token_via_body():
    request_token = {"oauth_token": "1", "oauth_token_secret": "2"}

    def assert_func(request):
        auth_header = request.headers.get("authorization")
        assert auth_header is None

        assert_valid_signature(request)

        content = request.form
        assert content.get("oauth_consumer_key") == "id"
        assert "oauth_signature" in content
        assert all(
            len(values) == 1
            for key, values in content.lists()
            if key.startswith("oauth_")
        )

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
        assert all(
            len(values) == 1
            for key, values in request.args.lists()
            if key.startswith("oauth_")
        )
        assert_valid_signature(request)

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
        response = client.get("https://resource.test/")

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
        response = client.post("https://resource.test/")

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
        response = client.get("https://resource.test/")

    assert response.content == b"hello"
    request = response.request
    auth_header = request.headers.get("authorization")
    assert auth_header is None

    url = str(request.url)
    assert "oauth_token=foo" in url
    assert "oauth_consumer_key=id" in url
    assert "oauth_signature=" in url
