import pytest

from authlib.oauth2 import rfc8414
from authlib.oauth2 import rfc9207


def test_validate_authorization_response_iss_parameter_supported():
    metadata = rfc9207.AuthorizationServerMetadata()
    metadata.validate_authorization_response_iss_parameter_supported()

    metadata = rfc9207.AuthorizationServerMetadata(
        {"authorization_response_iss_parameter_supported": True}
    )
    metadata.validate_authorization_response_iss_parameter_supported()

    metadata = rfc9207.AuthorizationServerMetadata(
        {"authorization_response_iss_parameter_supported": False}
    )
    metadata.validate_authorization_response_iss_parameter_supported()

    metadata = rfc9207.AuthorizationServerMetadata(
        {"authorization_response_iss_parameter_supported": "invalid"}
    )
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate_authorization_response_iss_parameter_supported()


def test_metadata_classes_composition():
    base_metadata = {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/auth",
        "token_endpoint": "https://provider.test/token",
        "response_types_supported": ["code"],
    }

    metadata = rfc8414.AuthorizationServerMetadata(
        {**base_metadata, "authorization_response_iss_parameter_supported": True}
    )
    metadata.validate(metadata_classes=[rfc9207.AuthorizationServerMetadata])

    metadata = rfc8414.AuthorizationServerMetadata(
        {**base_metadata, "authorization_response_iss_parameter_supported": "invalid"}
    )
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[rfc9207.AuthorizationServerMetadata])
