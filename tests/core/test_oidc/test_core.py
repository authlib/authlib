import unittest

import pytest

from authlib.jose.errors import InvalidClaimError
from authlib.jose.errors import MissingClaimError
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo
from authlib.oidc.core import get_claim_cls_by_response_type


class IDTokenTest(unittest.TestCase):
    def test_essential_claims(self):
        claims = CodeIDToken({}, {})
        with pytest.raises(MissingClaimError):
            claims.validate()
        claims = CodeIDToken(
            {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
        )
        claims.validate(1000)

    def test_validate_auth_time(self):
        claims = CodeIDToken(
            {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
        )
        claims.params = {"max_age": 100}
        with pytest.raises(MissingClaimError):
            claims.validate(1000)

        claims["auth_time"] = "foo"
        with pytest.raises(InvalidClaimError):
            claims.validate(1000)

    def test_validate_nonce(self):
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

    def test_validate_amr(self):
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

    def test_validate_azp(self):
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

    def test_validate_at_hash(self):
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

        # invalid alg won't raise
        claims.header = {"alg": "HS222"}
        claims.validate(1000)

        claims.header = {"alg": "HS256"}
        with pytest.raises(InvalidClaimError):
            claims.validate(1000)

    def test_implicit_id_token(self):
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

    def test_hybrid_id_token(self):
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

        # invalid alg won't raise
        claims.header = {"alg": "HS222"}
        claims["c_hash"] = "a"
        claims.validate(1000)

        claims.header = {"alg": "HS256"}
        with pytest.raises(InvalidClaimError):
            claims.validate(1000)

    def test_get_claim_cls_by_response_type(self):
        cls = get_claim_cls_by_response_type("id_token")
        assert cls == ImplicitIDToken
        cls = get_claim_cls_by_response_type("code")
        assert cls == CodeIDToken
        cls = get_claim_cls_by_response_type("code id_token")
        assert cls == HybridIDToken
        cls = get_claim_cls_by_response_type("none")
        assert cls is None


class UserInfoTest(unittest.TestCase):
    def test_getattribute(self):
        user = UserInfo({"sub": "1"})
        assert user.sub == "1"
        assert user.email is None
        with pytest.raises(AttributeError):
            user.invalid  # noqa: B018
