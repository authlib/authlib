import pytest

from authlib.oidc import discovery
from authlib.oidc import prompt_create


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


def validate(metadata):
    metadata = discovery.OpenIDProviderMetadata(metadata)
    metadata.validate(metadata_classes=[prompt_create.OpenIDProviderMetadata])


def test_prompt_values_supported(valid_oidc_metadata):
    """prompt_values_supported with 'create' is accepted."""
    valid_oidc_metadata["prompt_values_supported"] = ["none", "login", "create"]
    validate(valid_oidc_metadata)


@pytest.mark.parametrize("metadata", [{}, {"prompt_values_supported": None}])
def test_prompt_values_supported_missing(valid_oidc_metadata, metadata):
    """prompt_values_supported is required."""
    valid_oidc_metadata.update(metadata)
    with pytest.raises(ValueError, match="required"):
        validate(valid_oidc_metadata)


def test_prompt_values_supported_not_an_array(valid_oidc_metadata):
    """prompt_values_supported must be an array."""
    valid_oidc_metadata["prompt_values_supported"] = "create"
    with pytest.raises(ValueError, match="JSON array"):
        validate(valid_oidc_metadata)


def test_prompt_values_supported_not_strings(valid_oidc_metadata):
    """prompt_values_supported must contain strings."""
    valid_oidc_metadata["prompt_values_supported"] = ["create", 1]
    with pytest.raises(ValueError, match="strings"):
        validate(valid_oidc_metadata)


def test_prompt_values_supported_without_create(valid_oidc_metadata):
    """prompt_values_supported must contain 'create'."""
    valid_oidc_metadata["prompt_values_supported"] = ["none", "login"]
    with pytest.raises(ValueError, match="create"):
        validate(valid_oidc_metadata)
