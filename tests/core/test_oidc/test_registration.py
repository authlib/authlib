from unittest import TestCase

import pytest

from authlib.jose.errors import InvalidClaimError
from authlib.oidc.registration import ClientMetadataClaims


class ClientMetadataClaimsTest(TestCase):
    def test_request_uris(self):
        claims = ClientMetadataClaims(
            {"request_uris": ["https://client.test/request_uris"]}, {}
        )
        claims.validate()

        claims = ClientMetadataClaims({"request_uris": ["invalid"]}, {})
        with pytest.raises(InvalidClaimError):
            claims.validate()

    def test_initiate_login_uri(self):
        claims = ClientMetadataClaims(
            {"initiate_login_uri": "https://client.test/initiate_login_uri"}, {}
        )
        claims.validate()

        claims = ClientMetadataClaims({"initiate_login_uri": "invalid"}, {})
        with pytest.raises(InvalidClaimError):
            claims.validate()

    def test_token_endpoint_auth_signing_alg(self):
        claims = ClientMetadataClaims({"token_endpoint_auth_signing_alg": "RSA256"}, {})
        claims.validate()

        # The value none MUST NOT be used.
        claims = ClientMetadataClaims({"token_endpoint_auth_signing_alg": "none"}, {})
        with pytest.raises(InvalidClaimError):
            claims.validate()

    def test_id_token_signed_response_alg(self):
        claims = ClientMetadataClaims({"id_token_signed_response_alg": "RSA256"}, {})
        claims.validate()

    def test_default_max_age(self):
        claims = ClientMetadataClaims({"default_max_age": 1234}, {})
        claims.validate()

        # The value none MUST NOT be used.
        claims = ClientMetadataClaims({"default_max_age": "invalid"}, {})
        with pytest.raises(InvalidClaimError):
            claims.validate()
