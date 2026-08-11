"""Unit tests for AsyncOpenIDMixin kid handling (no starlette dependency)."""
import asyncio
import time

import pytest
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import OctKey

from authlib.integrations.base_client.async_openid import AsyncOpenIDMixin


def _make_id_token(signing_key, kid=None):
    """Create a signed ID token.

    :param signing_key: OctKey used to sign the token.
    :param kid: kid to include in the JWT header.  None omits it.
    """
    now = int(time.time())
    claims = {
        "sub": "user-42",
        "nonce": "n",
        "iss": "https://issuer.test",
        "aud": "client-1",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
    }
    header = {"alg": "HS256"}
    if kid is not None:
        header["kid"] = kid
    return jwt.encode(header, claims, signing_key)


class FakeAsyncClient(AsyncOpenIDMixin):
    def __init__(self, jwks, jwks_uri=None, refreshed_jwks=None):
        self.client_id = "client-1"
        self.server_metadata = {
            "jwks": jwks,
            "issuer": "https://issuer.test",
            "id_token_signing_alg_values_supported": ["HS256"],
        }
        if jwks_uri:
            self.server_metadata["jwks_uri"] = jwks_uri
        self._refreshed_jwks = refreshed_jwks or jwks

    async def load_server_metadata(self):
        return self.server_metadata

    async def fetch_jwk_set(self, force=False):
        if force:
            uri = self.server_metadata.get("jwks_uri")
            if not uri:
                raise RuntimeError('Missing "jwks_uri" in metadata')
            self.server_metadata["jwks"] = self._refreshed_jwks
            return self._refreshed_jwks
        return self.server_metadata["jwks"]


def test_async_default_raises_on_kid_mismatch():
    """Default: kid mismatch raises InvalidKeyIdError after refresh."""
    signing_key = OctKey.import_key("secret-for-async-mismatch")
    key_dict = signing_key.as_dict()
    key_dict["kid"] = "wrong-kid"
    extra_key = OctKey.import_key("extra-async-key-material")
    extra_dict = extra_key.as_dict()
    extra_dict["kid"] = "extra-kid"
    jwks = {"keys": [key_dict, extra_dict]}
    client = FakeAsyncClient(jwks, jwks_uri="https://issuer.test/jwks")
    token = {"id_token": _make_id_token(signing_key, kid="token-kid-1"), "access_token": "at"}

    with pytest.raises(InvalidKeyIdError):
        asyncio.run(client.parse_id_token(token, nonce="n"))


def test_async_no_kid_in_token_needs_fallback():
    """Token without kid + multiple JWKS keys raises unless fallback enabled."""
    signing_key = OctKey.import_key("secret-for-async-multi-key")
    other_key = OctKey.import_key("other-async-key-material")
    other_dict = other_key.as_dict()
    other_dict["kid"] = "key-1"
    correct_dict = signing_key.as_dict()
    correct_dict["kid"] = "key-2"
    jwks = {"keys": [other_dict, correct_dict]}

    client = FakeAsyncClient(jwks, jwks_uri="https://issuer.test/jwks")
    client.should_try_all_keys = lambda: True
    token = {"id_token": _make_id_token(signing_key, kid=None), "access_token": "at"}

    user = asyncio.run(client.parse_id_token(token, nonce="n"))
    assert user["sub"] == "user-42"


def test_async_try_all_keys_with_kid_mismatch():
    """With should_try_all_keys enabled, fallback finds correct key."""
    signing_key = OctKey.import_key("secret-for-async-try-all")
    key_dict = signing_key.as_dict()
    key_dict["kid"] = "wrong-kid"
    wrong_key = OctKey.import_key("wrong-async-key-material")
    wrong_dict = wrong_key.as_dict()
    wrong_dict["kid"] = "wrong-kid-2"
    jwks = {"keys": [key_dict, wrong_dict]}
    client = FakeAsyncClient(jwks, jwks_uri="https://issuer.test/jwks")
    client.should_try_all_keys = lambda: True
    token = {"id_token": _make_id_token(signing_key, kid="nonexistent-kid"), "access_token": "at"}

    user = asyncio.run(client.parse_id_token(token, nonce="n"))
    assert user["sub"] == "user-42"


def test_async_try_all_keys_when_jwks_key_has_no_kid():
    """With should_try_all_keys enabled, works when JWKS keys lack kid."""
    signing_key = OctKey.import_key("secret-for-async-no-kid-jwks")
    wrong_key = OctKey.import_key("wrong-async-no-kid-key")
    # JWKS keys have no kid — triggers InvalidKeyIdError for token with kid
    jwks = {"keys": [wrong_key.as_dict(), signing_key.as_dict()]}
    client = FakeAsyncClient(jwks, jwks_uri="https://issuer.test/jwks")
    client.should_try_all_keys = lambda: True
    token = {"id_token": _make_id_token(signing_key, kid="token-kid"), "access_token": "at"}

    user = asyncio.run(client.parse_id_token(token, nonce="n"))
    assert user["sub"] == "user-42"


def test_async_key_rotation_via_refresh():
    """JWKS refresh resolves kid mismatch from key rotation."""
    signing_key = OctKey.import_key("secret-for-async-rotation")
    old_key = OctKey.import_key("old-key-material-xxxxxxx")
    old_dict = old_key.as_dict()
    old_dict["kid"] = "old-kid"
    old_key2 = OctKey.import_key("old-key-material-zzzzzzz")
    old_dict2 = old_key2.as_dict()
    old_dict2["kid"] = "old-kid-2"

    correct_dict = signing_key.as_dict()
    correct_dict["kid"] = "new-kid"

    client = FakeAsyncClient(
        {"keys": [old_dict, old_dict2]},
        jwks_uri="https://issuer.test/jwks",
        refreshed_jwks={"keys": [correct_dict, old_dict2]},
    )
    token = {"id_token": _make_id_token(signing_key, kid="new-kid"), "access_token": "at"}

    user = asyncio.run(client.parse_id_token(token, nonce="n"))
    assert user["sub"] == "user-42"
