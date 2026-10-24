import httpx2
import pytest

from authlib.integrations.httpx_client import AssertionClient
from authlib.integrations.httpx_client import AsyncAssertionClient
from authlib.integrations.httpx_client import AsyncOAuth1Client
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuth1Client
from authlib.integrations.httpx_client import OAuth2Client

RealAsyncClient = httpx2.AsyncClient
RealClient = httpx2.Client


class InstrumentedAsyncClient(RealAsyncClient):
    """Mimics opentelemetry-instrumentation-httpx and aws-xray, which
    replace httpx2.AsyncClient with a subclass calling super().__init__."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class InstrumentedClient(RealClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


@pytest.fixture
def instrumented_httpx(monkeypatch):
    monkeypatch.setattr(httpx2, "AsyncClient", InstrumentedAsyncClient)
    monkeypatch.setattr(httpx2, "Client", InstrumentedClient)


def assert_real_httpx_init(client, real_class):
    assert isinstance(client, real_class)
    assert isinstance(client.headers, httpx2.Headers)
    assert isinstance(client.timeout, httpx2.Timeout)
    assert client.timeout.connect == 9


def test_async_oauth2_client_with_instrumented_httpx(instrumented_httpx):
    client = AsyncOAuth2Client("foo", timeout=9)
    assert_real_httpx_init(client, RealAsyncClient)


def test_oauth2_client_with_instrumented_httpx(instrumented_httpx):
    client = OAuth2Client("foo", timeout=9)
    assert_real_httpx_init(client, RealClient)


def test_async_oauth1_client_with_instrumented_httpx(instrumented_httpx):
    client = AsyncOAuth1Client("foo", timeout=9)
    assert_real_httpx_init(client, RealAsyncClient)


def test_oauth1_client_with_instrumented_httpx(instrumented_httpx):
    client = OAuth1Client("foo", timeout=9)
    assert_real_httpx_init(client, RealClient)


def test_async_assertion_client_with_instrumented_httpx(instrumented_httpx):
    client = AsyncAssertionClient("https://as.test/token", "iss", "sub", timeout=9)
    assert_real_httpx_init(client, RealAsyncClient)


def test_assertion_client_with_instrumented_httpx(instrumented_httpx):
    client = AssertionClient("https://as.test/token", "iss", "sub", timeout=9)
    assert_real_httpx_init(client, RealClient)
