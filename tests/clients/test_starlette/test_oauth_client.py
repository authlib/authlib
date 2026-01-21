import json

import pytest
from httpx import ASGITransport
from starlette.config import Config
from starlette.datastructures import URL
from starlette.requests import Request

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client import OAuthError

from ..asgi_helper import AsyncPathMapDispatch
from ..util import get_bearer_token


class AsyncDummyCache:
    """Simple async cache for testing."""

    def __init__(self):
        self._data = {}

    async def get(self, key):
        return self._data.get(key)

    async def set(self, key, value, expires_in=None):
        self._data[key] = value

    async def delete(self, key):
        self._data.pop(key, None)


def test_register_remote_app():
    oauth = OAuth()
    with pytest.raises(AttributeError):
        assert oauth.dev.name == "dev"

    oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
    )
    assert oauth.dev.name == "dev"
    assert oauth.dev.client_id == "dev"


def test_register_with_config():
    config = Config(environ={"DEV_CLIENT_ID": "dev"})
    oauth = OAuth(config)
    oauth.register("dev")
    assert oauth.dev.name == "dev"
    assert oauth.dev.client_id == "dev"


def test_register_with_overwrite():
    config = Config(environ={"DEV_CLIENT_ID": "dev"})
    oauth = OAuth(config)
    oauth.register("dev", client_id="not-dev", overwrite=True)
    assert oauth.dev.name == "dev"
    assert oauth.dev.client_id == "dev"


@pytest.mark.asyncio
async def test_oauth1_authorize():
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/request-token": {"body": "oauth_token=foo&oauth_verifier=baz"},
                "/token": {"body": "oauth_token=a&oauth_token_secret=b"},
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        request_token_url="https://provider.test/request-token",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, "https://client.test/callback")
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    assert "oauth_token=foo" in url
    assert "_state_dev_foo" in req.session
    req.scope["query_string"] = "oauth_token=foo&oauth_verifier=baz"
    token = await client.authorize_access_token(req)
    assert token["oauth_token"] == "a"


@pytest.mark.asyncio
async def test_oauth2_authorize():
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch({"/token": {"body": get_bearer_token()}})
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, "https://client.test/callback")
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    assert "state=" in url
    state = dict(url_decode(urlparse.urlparse(url).query))["state"]

    assert f"_state_dev_{state}" in req.session

    req_scope.update(
        {
            "path": "/",
            "query_string": f"code=a&state={state}",
            "session": req.session,
        }
    )
    req = Request(req_scope)
    token = await client.authorize_access_token(req)
    assert token["access_token"] == "a"


@pytest.mark.asyncio
async def test_oauth2_authorize_access_denied():
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch({"/token": {"body": get_bearer_token()}})
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req = Request(
        {
            "type": "http",
            "session": {},
            "path": "/",
            "query_string": "error=access_denied&error_description=Not+Allowed",
        }
    )
    with pytest.raises(OAuthError):
        await client.authorize_access_token(req)


@pytest.mark.asyncio
async def test_oauth2_authorize_code_challenge():
    transport = ASGITransport(
        AsyncPathMapDispatch({"/token": {"body": get_bearer_token()}})
    )
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "code_challenge_method": "S256",
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)

    resp = await client.authorize_redirect(
        req, redirect_uri="https://client.test/callback"
    )
    assert resp.status_code == 302

    url = resp.headers.get("Location")
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url

    state = dict(url_decode(urlparse.urlparse(url).query))["state"]
    state_data = req.session[f"_state_dev_{state}"]["data"]

    verifier = state_data["code_verifier"]
    assert verifier is not None

    req_scope.update(
        {
            "path": "/",
            "query_string": f"code=a&state={state}".encode(),
            "session": req.session,
        }
    )
    req = Request(req_scope)

    token = await client.authorize_access_token(req)
    assert token["access_token"] == "a"


@pytest.mark.asyncio
async def test_with_fetch_token_in_register():
    async def fetch_token(request):
        return {"access_token": "dev", "token_type": "bearer"}

    transport = ASGITransport(AsyncPathMapDispatch({"/user": {"body": {"sub": "123"}}}))
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        fetch_token=fetch_token,
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.get("/user", request=req)
    assert resp.json()["sub"] == "123"


@pytest.mark.asyncio
async def test_with_fetch_token_in_oauth():
    async def fetch_token(name, request):
        return {"access_token": "dev", "token_type": "bearer"}

    transport = ASGITransport(AsyncPathMapDispatch({"/user": {"body": {"sub": "123"}}}))
    oauth = OAuth(fetch_token=fetch_token)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.get("/user", request=req)
    assert resp.json()["sub"] == "123"


@pytest.mark.asyncio
async def test_request_withhold_token():
    oauth = OAuth()
    transport = ASGITransport(AsyncPathMapDispatch({"/user": {"body": {"sub": "123"}}}))
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "transport": transport,
        },
    )
    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.get("/user", request=req, withhold_token=True)
    assert resp.json()["sub"] == "123"


@pytest.mark.asyncio
async def test_oauth2_authorize_no_url():
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
    )
    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    with pytest.raises(RuntimeError):
        await client.create_authorization_url(req)


@pytest.mark.asyncio
async def test_oauth2_authorize_with_metadata():
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "authorization_endpoint": "https://provider.test/authorize"
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )
    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, "https://client.test/callback")
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_oauth2_authorize_form_post_callback():
    """Test that POST callbacks (form_post response mode) work properly."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch({"/token": {"body": get_bearer_token()}})
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req = Request({"type": "http", "session": {}})
    resp = await client.authorize_redirect(req, "https://client.test/callback")
    url = resp.headers.get("Location")
    state = dict(url_decode(urlparse.urlparse(url).query))["state"]

    req_scope_post = {
        "type": "http",
        "method": "POST",
        "path": "/callback",
        "query_string": b"",
        "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        "session": req.session,
    }

    async def receive():
        return {
            "type": "http.request",
            "body": f"code=test_code&state={state}".encode(),
        }

    req_post = Request(req_scope_post, receive=receive)

    token = await client.authorize_access_token(req_post)
    assert token["access_token"] == "a"


@pytest.mark.asyncio
async def test_logout_redirect():
    """Test logout_redirect generates correct URL with state stored in session."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.logout_redirect(
        req,
        post_logout_redirect_uri="https://client.test/logged-out",
        id_token_hint="fake.id.token",
    )
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    assert "https://provider.test/logout" in url
    assert "id_token_hint=fake.id.token" in url
    assert "post_logout_redirect_uri" in url
    assert "state=" in url

    # Verify state is stored in session
    params = dict(url_decode(urlparse.urlparse(url).query))
    state = params["state"]
    assert f"_state_dev_{state}" in req.session


@pytest.mark.asyncio
async def test_logout_redirect_without_redirect_uri():
    """Test logout_redirect omits state when no post_logout_redirect_uri is provided."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.logout_redirect(req, id_token_hint="fake.id.token")
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    assert "id_token_hint=fake.id.token" in url
    assert "state" not in url


@pytest.mark.asyncio
async def test_logout_redirect_missing_endpoint():
    """Test logout_redirect raises RuntimeError when end_session_endpoint is missing."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "authorization_endpoint": "https://provider.test/authorize",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    with pytest.raises(RuntimeError, match='Missing "end_session_endpoint"'):
        await client.logout_redirect(req)


@pytest.mark.asyncio
async def test_validate_logout_response():
    """Test validate_logout_response verifies state and returns stored data."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.logout_redirect(
        req,
        post_logout_redirect_uri="https://client.test/logged-out",
    )
    url = resp.headers.get("Location")
    params = dict(url_decode(urlparse.urlparse(url).query))
    state = params["state"]

    req_scope2 = {
        "type": "http",
        "session": req.session,
        "query_string": f"state={state}",
    }
    req2 = Request(req_scope2)
    state_data = await client.validate_logout_response(req2)
    assert state_data["post_logout_redirect_uri"] == "https://client.test/logged-out"
    # State should be cleared from session
    assert f"_state_dev_{state}" not in req2.session


@pytest.mark.asyncio
async def test_validate_logout_response_missing_state():
    """Test validate_logout_response raises OAuthError when state is missing."""
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    req = Request({"type": "http", "session": {}, "query_string": ""})
    with pytest.raises(OAuthError, match='Missing "state" parameter'):
        await client.validate_logout_response(req)


@pytest.mark.asyncio
async def test_validate_logout_response_invalid_state():
    """Test validate_logout_response raises OAuthError when state is invalid."""
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    req = Request(
        {"type": "http", "session": {}, "query_string": "state=invalid-state"}
    )
    with pytest.raises(OAuthError, match='Invalid "state" parameter'):
        await client.validate_logout_response(req)


@pytest.mark.asyncio
async def test_logout_redirect_with_cache():
    """Test logout_redirect stores state in cache instead of session."""
    cache = AsyncDummyCache()
    oauth = OAuth(cache=cache)
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.logout_redirect(
        req,
        post_logout_redirect_uri="https://client.test/logged-out",
    )
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    params = dict(url_decode(urlparse.urlparse(url).query))
    state = params["state"]

    # With cache, data is in cache, not in session
    cache_key = f"_state_dev_{state}"
    cached_data = await cache.get(cache_key)
    assert cached_data is not None
    assert (
        json.loads(cached_data)["data"]["post_logout_redirect_uri"]
        == "https://client.test/logged-out"
    )


@pytest.mark.asyncio
async def test_logout_redirect_with_url_object():
    """Test logout_redirect handles URL objects for post_logout_redirect_uri."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    # Pass URL object instead of string
    redirect_uri = URL("https://client.test/logged-out")
    resp = await client.logout_redirect(
        req,
        post_logout_redirect_uri=redirect_uri,
    )
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    assert "post_logout_redirect_uri=https%3A%2F%2Fclient.test%2Flogged-out" in url


@pytest.mark.asyncio
async def test_validate_logout_response_with_cache():
    """Test validate_logout_response retrieves state from cache."""
    cache = AsyncDummyCache()
    oauth = OAuth(cache=cache)
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.logout_redirect(
        req,
        post_logout_redirect_uri="https://client.test/logged-out",
    )
    url = resp.headers.get("Location")
    params = dict(url_decode(urlparse.urlparse(url).query))
    state = params["state"]

    # Validate the response
    req2 = Request({"type": "http", "session": {}, "query_string": f"state={state}"})
    state_data = await client.validate_logout_response(req2)
    assert state_data["post_logout_redirect_uri"] == "https://client.test/logged-out"

    # Cache should be cleared
    cache_key = f"_state_dev_{state}"
    assert await cache.get(cache_key) is None


@pytest.mark.asyncio
async def test_logout_redirect_with_extra_params():
    """Test logout_redirect includes optional params: client_id, logout_hint, ui_locales."""
    oauth = OAuth()
    transport = ASGITransport(
        AsyncPathMapDispatch(
            {
                "/.well-known/openid-configuration": {
                    "body": {
                        "issuer": "https://provider.test",
                        "end_session_endpoint": "https://provider.test/logout",
                    }
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.logout_redirect(
        req,
        post_logout_redirect_uri="https://client.test/logged-out",
        client_id="dev",
        logout_hint="user@example.com",
        ui_locales="fr",
    )
    assert resp.status_code == 302
    url = resp.headers.get("Location")
    assert "client_id=dev" in url
    assert "logout_hint=user%40example.com" in url
    assert "ui_locales=fr" in url
