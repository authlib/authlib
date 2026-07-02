import pytest

from authlib.oidc.discovery.models import OpenIDProviderMetadata


def test_prompt_values_supported_accepts_create():
    data = {"prompt_values_supported": ["none", "login", "consent", "select_account", "create"]}
    metadata = OpenIDProviderMetadata(data)
    # Should not raise
    metadata.validate_prompt_values_supported()


def test_prompt_values_supported_rejects_invalid():
    data = {"prompt_values_supported": ["none", "bogus"]}
    metadata = OpenIDProviderMetadata(data)
    with pytest.raises(ValueError):
        metadata.validate_prompt_values_supported()
