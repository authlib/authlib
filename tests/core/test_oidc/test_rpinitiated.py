import pytest

from authlib.jose.errors import InvalidClaimError
from authlib.oidc.rpinitiated import ClientMetadataClaims
from authlib.oidc.rpinitiated import OpenIDProviderMetadata


def test_validate_end_session_endpoint():
    metadata = OpenIDProviderMetadata()
    metadata.validate_end_session_endpoint()

    metadata = OpenIDProviderMetadata(
        {"end_session_endpoint": "http://provider.test/end_session"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_end_session_endpoint()

    metadata = OpenIDProviderMetadata(
        {"end_session_endpoint": "https://provider.test/end_session"}
    )
    metadata.validate_end_session_endpoint()


def test_end_session_endpoint_missing():
    """Missing end_session_endpoint should be valid (optional)."""
    metadata = OpenIDProviderMetadata({})
    metadata.validate_end_session_endpoint()


def test_post_logout_redirect_uris():
    claims = ClientMetadataClaims(
        {"post_logout_redirect_uris": ["https://client.test/logout"]}, {}
    )
    claims.validate()

    claims = ClientMetadataClaims(
        {
            "post_logout_redirect_uris": [
                "https://client.test/logout",
                "https://client.test/logged-out",
            ]
        },
        {},
    )
    claims.validate()

    claims = ClientMetadataClaims({"post_logout_redirect_uris": ["invalid"]}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_post_logout_redirect_uris_empty():
    """Empty list should be valid."""
    claims = ClientMetadataClaims({"post_logout_redirect_uris": []}, {})
    claims.validate()


def test_post_logout_redirect_uris_insecure():
    """HTTP URIs should be rejected."""
    claims = ClientMetadataClaims(
        {"post_logout_redirect_uris": ["http://client.test/logout"]}, {}
    )
    with pytest.raises(ValueError):
        claims.validate()
