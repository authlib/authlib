import pytest

from authlib.jose.errors import InvalidClaimError
from authlib.oidc import discovery
from authlib.oidc import rpinitiated
from authlib.oidc.rpinitiated import ClientMetadataClaims


@pytest.fixture
def valid_oidc_metadata():
    return {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/authorize",
        "token_endpoint": "https://provider.test/token",
        "jwks_uri": "https://provider.test/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def test_validate_end_session_endpoint(valid_oidc_metadata):
    valid_oidc_metadata["end_session_endpoint"] = "https://provider.test/logout"
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    metadata.validate(metadata_classes=[rpinitiated.OpenIDProviderMetadata])


def test_validate_end_session_endpoint_missing(valid_oidc_metadata):
    """end_session_endpoint is optional."""
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    metadata.validate(metadata_classes=[rpinitiated.OpenIDProviderMetadata])


def test_validate_end_session_endpoint_insecure(valid_oidc_metadata):
    valid_oidc_metadata["end_session_endpoint"] = "http://provider.test/logout"
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    with pytest.raises(ValueError, match="https"):
        metadata.validate(metadata_classes=[rpinitiated.OpenIDProviderMetadata])


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


def test_post_logout_redirect_uris_insecure_public_client():
    """HTTP URIs should be rejected for public clients."""
    claims = ClientMetadataClaims(
        {
            "post_logout_redirect_uris": ["http://client.test/logout"],
            "token_endpoint_auth_method": "none",
        },
        {},
    )
    with pytest.raises(ValueError, match="public clients"):
        claims.validate()


def test_post_logout_redirect_uris_insecure_confidential_client():
    """HTTP URIs should be accepted for confidential clients."""
    claims = ClientMetadataClaims(
        {
            "post_logout_redirect_uris": ["http://client.test/logout"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
        {},
    )
    claims.validate()
