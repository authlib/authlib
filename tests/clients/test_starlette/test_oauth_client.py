import pytest
from httpx import ASGITransport
from starlette.config import Config
from starlette.requests import Request

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client import OAuthError

from ..asgi_helper import AsyncPathMapDispatch
from ..util import get_bearer_token


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
        request_token_url="https://i.b/request-token",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, "https://b.com/bar")
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, "https://b.com/bar")
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={
            "code_challenge_method": "S256",
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)

    resp = await client.authorize_redirect(req, redirect_uri="https://b.com/bar")
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
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
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
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
                    "body": {"authorization_endpoint": "https://i.b/authorize"}
                }
            }
        )
    )
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        server_metadata_url="https://i.b/.well-known/openid-configuration",
        client_kwargs={
            "transport": transport,
        },
    )
    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    resp = await client.authorize_redirect(req, "https://b.com/bar")
    assert resp.status_code == 302
