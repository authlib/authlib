import types

import pytest
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError

from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.grants import BaseGrant
from authlib.oauth2.rfc6749.grants import TokenEndpointMixin
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import OpenIDCode
from authlib.oidc.core import UserInfo
from authlib.oidc.core import get_claim_cls_by_response_type


def test_essential_claims():
    claims = CodeIDToken({}, {})
    with pytest.raises(MissingClaimError):
        claims.validate()
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.validate(1000)


def test_validate_auth_time():
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.params = {"max_age": 100}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    claims["auth_time"] = "foo"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_nonce():
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.params = {"nonce": "foo"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)
    claims["nonce"] = "bar"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)
    claims["nonce"] = "foo"
    claims.validate(1000)


def test_validate_amr():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "amr": "invalid",
        },
        {},
    )
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_azp():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
        },
        {},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    claims["azp"] = "1"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims["azp"] = "2"
    claims.validate(1000)


def test_validate_at_hash():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "at_hash": "a",
        },
        {},
    )
    claims.params = {"access_token": "a"}

    # invalid alg will raise too
    claims.header = {"alg": "HS222"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims.header = {"alg": "HS256"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_implicit_id_token():
    claims = ImplicitIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "nonce": "a",
        },
        {},
    )
    claims.params = {"access_token": "a"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)


def test_hybrid_id_token():
    claims = HybridIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "nonce": "a",
        },
        {},
    )
    claims.validate(1000)

    claims.params = {"code": "a"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    # invalid alg will raise too
    claims.header = {"alg": "HS222"}
    claims["c_hash"] = "a"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims.header = {"alg": "HS256"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_get_claim_cls_by_response_type():
    cls = get_claim_cls_by_response_type("id_token")
    assert cls == ImplicitIDToken
    cls = get_claim_cls_by_response_type("code")
    assert cls == CodeIDToken
    cls = get_claim_cls_by_response_type("code id_token")
    assert cls == HybridIDToken
    cls = get_claim_cls_by_response_type("token id_token")
    assert cls == ImplicitIDToken
    cls = get_claim_cls_by_response_type("token id_token code")
    assert cls == HybridIDToken
    cls = get_claim_cls_by_response_type("code code")
    assert cls is None
    cls = get_claim_cls_by_response_type(None)
    assert cls is None
    cls = get_claim_cls_by_response_type("none")
    assert cls is None


def test_userinfo_getattribute():
    user = UserInfo({"sub": "1"})
    assert user.sub == "1"
    assert user.email is None
    with pytest.raises(AttributeError):
        user.invalid  # noqa: B018


def test_userinfo_validate_locale():
    UserInfo({"sub": "1"}).validate_locale()
    UserInfo({"sub": "1", "locale": "en"}).validate_locale()
    UserInfo({"sub": "1", "locale": "en-US"}).validate_locale()
    UserInfo({"sub": "1", "locale": "zh-Hans-CN"}).validate_locale()
    UserInfo({"sub": "1", "locale": "x-custom"}).validate_locale()

    with pytest.raises(ValueError, match="BCP 47"):
        UserInfo({"sub": "1", "locale": "fr_FR"}).validate_locale()

    with pytest.raises(ValueError, match="BCP 47"):
        UserInfo({"sub": "1", "locale": "toolongsubtag"}).validate_locale()


def test_openid_code_on_custom_grant(monkeypatch):
    """OpenIDCode extends a grant that does not inherit AuthorizationCodeGrant."""
    calls = []

    class CustomCodeGrant(AuthorizationEndpointMixin, TokenEndpointMixin, BaseGrant):
        def validate_authorization_request_payload(self, redirect_uri):
            pass

        def validate_consent_request(self):
            return "https://client.test/cb"

        def create_token_response(self):
            return "token response"

    class RecordingOpenIDCode(OpenIDCode):
        def validate_openid_authorization_request(self, grant, redirect_uri):
            calls.append(("validate_openid_authorization_request", redirect_uri))

        def process_token(self, grant, response):
            calls.append(("process_token", response))

    monkeypatch.setattr(
        "authlib.oidc.core.grants.code.validate_request_prompt",
        lambda grant, redirect_uri: calls.append(
            ("validate_request_prompt", redirect_uri)
        ),
    )
    request = types.SimpleNamespace(payload=types.SimpleNamespace(scope="openid"))
    grant = CustomCodeGrant(request, None)
    RecordingOpenIDCode()(grant)

    grant.validate_authorization_request_payload("https://client.test/cb")
    grant.validate_consent_request()
    grant.create_token_response()

    assert calls == [
        ("validate_openid_authorization_request", None),
        ("validate_request_prompt", "https://client.test/cb"),
        ("process_token", "token response"),
    ]
