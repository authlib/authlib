from unittest import mock

import httpx2
import pytest
from starlette.datastructures import URL as StarletteURL

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuth1Client as HttpxOAuth1Client
from authlib.integrations.httpx_client import OAuth2Client as HttpxOAuth2Client
from authlib.integrations.requests_client import OAuth1Session
from authlib.integrations.requests_client import OAuth2Session

from .util import mock_text_response

URL_TYPES = [httpx2.URL, StarletteURL]
CALLBACK = "https://client.test/callback"
TOKEN = {"access_token": "a", "refresh_token": "r", "token_type": "bearer"}


def _query(url):
    return dict(url_decode(urlparse.urlparse(url).query))


def _token_session(sent):
    session = OAuth2Session("client-id", "client-secret")

    def fake_send(request, **kwargs):
        sent.append(request)
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.json = lambda: TOKEN
        return resp

    session.send = fake_send
    return session


def _httpx_transport(sent):
    def handler(request):
        sent.append(request)
        if "request" in request.url.path:
            return httpx2.Response(200, text="oauth_token=t&oauth_token_secret=s")

        return httpx2.Response(200, json=TOKEN)

    return httpx2.MockTransport(handler)


@pytest.mark.parametrize("url_type", URL_TYPES)
@pytest.mark.parametrize("client_cls", [OAuth2Session, HttpxOAuth2Client])
def test_oauth2_authorization_url(client_cls, url_type):
    """create_authorization_url accepts URL objects."""
    with client_cls("client-id", redirect_uri=url_type(CALLBACK)) as client:
        url, _ = client.create_authorization_url(
            url_type("https://provider.test/authorize")
        )
        assert url.startswith("https://provider.test/authorize?")
        assert _query(url)["redirect_uri"] == CALLBACK

        client.redirect_uri = url_type(CALLBACK)
        assert client.redirect_uri == CALLBACK

        url, _ = client.create_authorization_url(
            "https://provider.test/authorize", redirect_uri=url_type(CALLBACK)
        )
        assert _query(url)["redirect_uri"] == CALLBACK


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_oauth2_fetch_token(url_type):
    """fetch_token accepts URL objects for the authorization response and
    the redirect URI."""
    sent = []
    session = _token_session(sent)
    session.redirect_uri = url_type(CALLBACK)
    session.fetch_token(
        url_type("https://provider.test/token"),
        authorization_response=url_type(f"{CALLBACK}?code=c"),
    )
    assert url_decode(sent[-1].body)[0:2] == [
        ("grant_type", "authorization_code"),
        ("redirect_uri", CALLBACK),
    ]

    session.fetch_token(
        "https://provider.test/token", code="c", redirect_uri=url_type(CALLBACK)
    )
    assert ("redirect_uri", CALLBACK) in url_decode(sent[-1].body)


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_oauth2_fetch_token_from_fragment(url_type):
    """An implicit authorization response can be a URL object."""
    session = OAuth2Session("client-id")
    token = session.fetch_token(
        authorization_response=url_type(f"{CALLBACK}#access_token=a&token_type=bearer")
    )
    assert token["access_token"] == "a"


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_oauth2_fetch_token_with_get(url_type):
    """A token request with GET accepts a URL object."""
    sent = []
    session = _token_session(sent)
    session.fetch_token(
        url_type("https://provider.test/token?a=b"), method="GET", code="c"
    )
    assert _query(sent[-1].url)["code"] == "c"


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_httpx_oauth2_token_endpoints(url_type):
    """The httpx client accepts URL objects for every token endpoint."""
    sent = []
    with HttpxOAuth2Client(
        "client-id", "client-secret", transport=_httpx_transport(sent)
    ) as client:
        client.fetch_token(
            url_type("https://provider.test/token"), grant_type="client_credentials"
        )
        client.refresh_token(url_type("https://provider.test/token"))
        client.revoke_token(url_type("https://provider.test/revoke"))
        client.introspect_token(url_type("https://provider.test/introspect"))

    assert [request.url.path for request in sent] == [
        "/token",
        "/token",
        "/revoke",
        "/introspect",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("url_type", URL_TYPES)
async def test_async_oauth2_fetch_token_with_get(url_type):
    """The async client accepts a URL object for a token request with GET."""
    sent = []
    async with AsyncOAuth2Client(
        "client-id", "client-secret", transport=_httpx_transport(sent)
    ) as client:
        await client.fetch_token(
            url_type("https://provider.test/token"),
            method="GET",
            grant_type="client_credentials",
        )

    assert sent[-1].url.params["grant_type"] == "client_credentials"


@pytest.mark.parametrize("url_type", URL_TYPES)
@pytest.mark.parametrize("client_cls", [OAuth1Session, HttpxOAuth1Client])
def test_oauth1_authorization_url(client_cls, url_type):
    """create_authorization_url accepts URL objects."""
    with client_cls("client-id", redirect_uri=url_type(CALLBACK)) as client:
        url = client.create_authorization_url(
            url_type("https://provider.test/authorize"), request_token="t"
        )
        assert url.startswith("https://provider.test/authorize?")
        assert _query(url)["oauth_callback"] == CALLBACK

        client.redirect_uri = url_type(CALLBACK)
        assert client.redirect_uri == CALLBACK


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_oauth1_fetch_request_token(url_type):
    """The callback signed in the request token request can be a URL object."""
    session = OAuth1Session("client-id", "secret", redirect_uri=url_type(CALLBACK))
    session.send = mock_text_response("oauth_token=t&oauth_token_secret=s")
    token = session.fetch_request_token(url_type("https://provider.test/request"))
    assert token["oauth_token"] == "t"


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_httpx_oauth1_fetch_request_token(url_type):
    """The httpx client accepts a URL object for the request token endpoint."""
    sent = []
    with HttpxOAuth1Client(
        "client-id", "secret", transport=_httpx_transport(sent)
    ) as client:
        token = client.fetch_request_token(url_type("https://provider.test/request"))

    assert token["oauth_token"] == "t"


@pytest.mark.parametrize("url_type", URL_TYPES)
def test_oauth1_parse_authorization_response(url_type):
    """parse_authorization_response accepts a URL object."""
    session = OAuth1Session("client-id")
    token = session.parse_authorization_response(
        url_type(f"{CALLBACK}?oauth_token=t&oauth_verifier=v")
    )
    assert token == {"oauth_token": "t", "oauth_verifier": "v"}
