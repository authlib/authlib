import time

import pytest
from httpx import ASGITransport
from joserfc import jwk
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet
from starlette.requests import Request

from authlib.integrations.starlette_client import OAuth
from authlib.oidc.core.grants.util import create_half_hash

from ..asgi_helper import AsyncPathMapDispatch
from ..util import get_bearer_token
from ..util import read_key_file

secret_key = jwk.import_key("test-oct-secret", "oct", {"kid": "f"})


async def run_fetch_userinfo(payload):
    oauth = OAuth()

    async def fetch_token(request):
        return get_bearer_token()

    transport = ASGITransport(AsyncPathMapDispatch({"/userinfo": {"body": payload}}))

    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=fetch_token,
        userinfo_endpoint="https://provider.test/userinfo",
        client_kwargs={
            "transport": transport,
        },
    )

    req_scope = {"type": "http", "session": {}}
    req = Request(req_scope)
    user = await client.userinfo(request=req)
    assert user.sub == "123"


@pytest.mark.asyncio
async def test_fetch_userinfo():
    await run_fetch_userinfo({"sub": "123"})


@pytest.mark.asyncio
async def test_parse_id_token():
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": "n",
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256"}, claims, secret_key)
    token["id_token"] = id_token

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256", "RS256"],
    )
    user = await client.parse_id_token(token, nonce="n")
    assert user.sub == "123"

    claims_options = {"iss": {"value": "https://provider.test"}}
    user = await client.parse_id_token(token, nonce="n", claims_options=claims_options)
    assert user.sub == "123"

    with pytest.raises(InvalidClaimError):
        claims_options = {"iss": {"value": "https://wrong-provider.test"}}
        await client.parse_id_token(token, nonce="n", claims_options=claims_options)


@pytest.mark.asyncio
async def test_runtime_error_fetch_jwks_uri():
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": "n",
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256"}, claims, secret_key)

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        issuer="https://provider.test",
        id_token_signing_alg_values_supported=["HS256"],
    )
    req_scope = {"type": "http", "session": {"_dev_authlib_nonce_": "n"}}
    req = Request(req_scope)
    token["id_token"] = id_token
    with pytest.raises(RuntimeError):
        await client.parse_id_token(req, token)


@pytest.mark.asyncio
async def test_force_fetch_jwks_uri():
    secret_keys = KeySet.import_key_set(read_key_file("jwks_private.json"))
    token = get_bearer_token()
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": "n",
        "at_hash": create_half_hash(token["access_token"], "RS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "RS256"}, claims, secret_keys)
    token["id_token"] = id_token

    transport = ASGITransport(
        AsyncPathMapDispatch({"/jwks": {"body": read_key_file("jwks_public.json")}})
    )

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        fetch_token=get_bearer_token,
        jwks={"keys": [secret_key.as_dict()]},
        jwks_uri="https://provider.test/jwks",
        issuer="https://provider.test",
        client_kwargs={
            "transport": transport,
        },
    )
    user = await client.parse_id_token(token, nonce="n")
    assert user.sub == "123"
