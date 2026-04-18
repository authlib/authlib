import pytest
from joserfc.errors import InvalidClaimError

from authlib.oauth2.rfc7591 import ClientMetadataClaims


def test_validate_redirect_uris():
    claims = ClientMetadataClaims({"redirect_uris": ["foo"]}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_validate_client_uri():
    claims = ClientMetadataClaims({"client_uri": "foo"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_validate_logo_uri():
    claims = ClientMetadataClaims({"logo_uri": "foo"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_validate_tos_uri():
    claims = ClientMetadataClaims({"tos_uri": "foo"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_validate_policy_uri():
    claims = ClientMetadataClaims({"policy_uri": "foo"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_validate_jwks_uri():
    claims = ClientMetadataClaims({"jwks_uri": "foo"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()
