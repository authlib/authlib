import unittest

import pytest

from authlib.oauth2.rfc9728 import ProtectedResourceMetadata
from authlib.oauth2.rfc9728.well_known import get_well_known_url

WELL_KNOWN_URL = "/.well-known/oauth-protected-resource"


class WellKnownTest(unittest.TestCase):
    def test_no_suffix_issuer(self):
        assert get_well_known_url("https://authlib.org") == WELL_KNOWN_URL
        assert get_well_known_url("https://authlib.org/") == WELL_KNOWN_URL

    def test_with_suffix_issuer(self):
        assert (
            get_well_known_url("https://authlib.org/issuer1")
            == WELL_KNOWN_URL + "/issuer1"
        )
        assert (
            get_well_known_url("https://authlib.org/a/b/c") == WELL_KNOWN_URL + "/a/b/c"
        )

    def test_with_external(self):
        assert (
            get_well_known_url("https://authlib.org", external=True)
            == "https://authlib.org" + WELL_KNOWN_URL
        )

    def test_with_changed_suffix(self):
        url = get_well_known_url("https://authlib.org", suffix="openid-configuration")
        assert url == "/.well-known/openid-configuration"
        url = get_well_known_url(
            "https://authlib.org", external=True, suffix="openid-configuration"
        )
        assert url == "https://authlib.org/.well-known/openid-configuration"


class ProtectedResourceMetadataTest(unittest.TestCase):
    def test_validate_resource(self):
        #: missing
        metadata = ProtectedResourceMetadata({})
        with pytest.raises(ValueError, match='"resource" is required'):
            metadata.validate()

        #: https
        metadata = ProtectedResourceMetadata(
            {"resource": "http://authlib.org/test-resource"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_resource()

        #: fragment
        metadata = ProtectedResourceMetadata(
            {"resource": "https://authlib.org/test-resource#fragment"}
        )
        with pytest.raises(ValueError, match="fragment"):
            metadata.validate_resource()

        metadata = ProtectedResourceMetadata(
            {"resource": "https://authlib.org/test-resource"}
        )
        metadata.validate_resource()

    def test_validate_authorization_servers(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_authorization_servers()

        # not a JSON array
        metadata = ProtectedResourceMetadata(
            {"authorization_servers": "https://authlib.org/"}
        )
        with pytest.raises(ValueError, match="MUST be JSON array"):
            metadata.validate_authorization_servers()

        # valid array
        metadata = ProtectedResourceMetadata(
            {"authorization_servers": ["https://authlib.org/"]}
        )
        metadata.validate_authorization_servers()

    def test_validate_jwks_uri(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_jwks_uri()
        # not https
        metadata = ProtectedResourceMetadata(
            {"jwks_uri": "http://authlib.org/jwks.json"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_jwks_uri()

        metadata = ProtectedResourceMetadata(
            {"jwks_uri": "https://authlib.org/jwks.json"}
        )
        metadata.validate_jwks_uri()

    def test_validate_scopes_supported(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_scopes_supported()

        # not array
        metadata = ProtectedResourceMetadata({"scopes_supported": "foo"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_scopes_supported()

        # valid
        metadata = ProtectedResourceMetadata({"scopes_supported": ["foo"]})
        metadata.validate_scopes_supported()

    def test_validate_bearer_methods_supported(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_scopes_supported()

        # not array
        metadata = ProtectedResourceMetadata({"bearer_methods_supported": "foo"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_bearer_methods_supported()

        # not supported value
        metadata = ProtectedResourceMetadata({"bearer_methods_supported": ["foo"]})
        with pytest.raises(ValueError, match="method"):
            metadata.validate_bearer_methods_supported()

        # empty array is valid
        metadata = ProtectedResourceMetadata({"bearer_methods_supported": []})
        metadata.validate_bearer_methods_supported()

        # valid
        metadata = ProtectedResourceMetadata(
            {"bearer_methods_supported": ["header", "body", "query"]}
        )
        metadata.validate_bearer_methods_supported()

    def test_validate_resource_signing_alg_values_supported(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_resource_signing_alg_values_supported()

        # not array
        metadata = ProtectedResourceMetadata(
            {"resource_signing_alg_values_supported": "foo"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_resource_signing_alg_values_supported()

        # forbidden none
        metadata = ProtectedResourceMetadata(
            {"resource_signing_alg_values_supported": ["none"]}
        )
        with pytest.raises(ValueError, match="none"):
            metadata.validate_resource_signing_alg_values_supported()

        # valid
        metadata = ProtectedResourceMetadata(
            {"resource_signing_alg_values_supported": ["RS256", "ES256"]}
        )
        metadata.validate_resource_signing_alg_values_supported()

    def test_validate_resource_name(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_resource_name()
        # not string
        metadata = ProtectedResourceMetadata({"resource_name": 123})
        with pytest.raises(ValueError, match="MUST be a string"):
            metadata.validate_resource_name()
        # valid
        metadata = ProtectedResourceMetadata({"resource_name": "my_resource"})
        metadata.validate_resource_name()

        # check internationalized resource_name - not string
        metadata = ProtectedResourceMetadata({"resource_name#en": 123})
        with pytest.raises(ValueError, match="MUST be a string"):
            metadata.validate_resource_name()

        # check internationalized resource_name - valid
        metadata = ProtectedResourceMetadata({"resource_name#fr": "ma_ressource"})
        metadata.validate_resource_name()

    def test_validate_resource_documentation(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_resource_documentation()

        # not a URL
        metadata = ProtectedResourceMetadata({"resource_documentation": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_documentation()

        # not a valid URL
        metadata = ProtectedResourceMetadata(
            {"resource_documentation": "http//authlib.org/test_resource"}
        )
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_documentation()
        # valid URL
        metadata = ProtectedResourceMetadata(
            {"resource_documentation": "https://authlib.org/"}
        )
        metadata.validate_resource_documentation()

        # check internationalized resource_documentation - not url
        metadata = ProtectedResourceMetadata({"resource_documentation#fr": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_documentation()

        # check internationalized resource_documentation - valid
        metadata = ProtectedResourceMetadata(
            {"resource_documentation#fr": "https://authlib.org/"}
        )
        metadata.validate_resource_documentation()

    def test_validate_resource_policy_uri(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_resource_policy_uri()

        # not a URL
        metadata = ProtectedResourceMetadata({"resource_policy_uri": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_policy_uri()

        # valid URL
        metadata = ProtectedResourceMetadata(
            {"resource_policy_uri": "https://authlib.org/"}
        )
        metadata.validate_resource_policy_uri()

    def test_validate_resource_tos_uri(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_resource_tos_uri()

        # not a URL
        metadata = ProtectedResourceMetadata({"resource_tos_uri": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_tos_uri()

        # valid URL
        metadata = ProtectedResourceMetadata(
            {"resource_tos_uri": "https://authlib.org/"}
        )
        metadata.validate_resource_tos_uri()

    def test_validate_tls_client_certificate_bound_access_tokens(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_tls_client_certificate_bound_access_tokens()

        # not a URL
        metadata = ProtectedResourceMetadata(
            {"tls_client_certificate_bound_access_tokens": "invalid"}
        )
        with pytest.raises(ValueError, match="MUST be a boolean"):
            metadata.validate_tls_client_certificate_bound_access_tokens()

        # valid URL
        metadata = ProtectedResourceMetadata(
            {"tls_client_certificate_bound_access_tokens": True}
        )
        metadata.validate_tls_client_certificate_bound_access_tokens()

    def test_validate_authorization_details_types_supported(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_authorization_details_types_supported()

        # not array
        metadata = ProtectedResourceMetadata(
            {"authorization_details_types_supported": "foo"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_authorization_details_types_supported()

        # valid
        metadata = ProtectedResourceMetadata(
            {"authorization_details_types_supported": ["foo"]}
        )
        metadata.validate_authorization_details_types_supported()

    def test_validate_dpop_signing_alg_values_supported(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_dpop_signing_alg_values_supported()

        # not array
        metadata = ProtectedResourceMetadata(
            {"dpop_signing_alg_values_supported": "foo"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_dpop_signing_alg_values_supported()

        # valid
        metadata = ProtectedResourceMetadata(
            {"dpop_signing_alg_values_supported": ["RS256", "ES256"]}
        )
        metadata.validate_dpop_signing_alg_values_supported()

    def test_validate_dpop_bound_access_tokens_required(self):
        # can missing
        metadata = ProtectedResourceMetadata()
        metadata.validate_dpop_bound_access_tokens_required()

        # not boolean
        metadata = ProtectedResourceMetadata(
            {"dpop_bound_access_tokens_required": "foo"}
        )
        with pytest.raises(ValueError, match="boolean"):
            metadata.validate_dpop_bound_access_tokens_required()

        # valid
        metadata = ProtectedResourceMetadata(
            {"dpop_bound_access_tokens_required": True}
        )
        metadata.validate_dpop_bound_access_tokens_required()

    def test_validate_resource_policy_uri_internationalized(self):
        # error case
        metadata = ProtectedResourceMetadata({"resource_policy_uri#es": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_policy_uri()

        # nominal case
        metadata = ProtectedResourceMetadata(
            {"resource_policy_uri#es": "https://authlib.org/"}
        )
        metadata.validate_resource_policy_uri()

    def test_validate_resource_tos_uri_internationalized(self):
        # error case
        metadata = ProtectedResourceMetadata({"resource_tos_uri#de": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_resource_tos_uri()

        # nominal case
        metadata = ProtectedResourceMetadata(
            {"resource_tos_uri#de": "https://authlib.org/"}
        )
        metadata.validate_resource_tos_uri()

    def test_properties_default_values(self):
        """Test default values for boolean properties."""
        metadata = ProtectedResourceMetadata({})

        assert metadata.tls_client_certificate_bound_access_tokens is False
        assert metadata.dpop_bound_access_tokens_required is False

        metadata = ProtectedResourceMetadata(
            {
                "tls_client_certificate_bound_access_tokens": True,
                "dpop_bound_access_tokens_required": True,
            }
        )
        assert metadata.tls_client_certificate_bound_access_tokens is True
        assert metadata.dpop_bound_access_tokens_required is True

    def test_getattr_registry_keys(self):
        metadata = ProtectedResourceMetadata(
            {
                "resource": "https://example.com/api",
                "scopes_supported": ["read", "write"],
            }
        )

        assert metadata.resource == "https://example.com/api"
        assert metadata.scopes_supported == ["read", "write"]
        assert metadata.authorization_servers is None

    def test_getattr_non_registry_keys(self):
        # test __getattr__ method for non-registry keys
        metadata = ProtectedResourceMetadata({})

        with pytest.raises(AttributeError):
            _ = metadata.non_existent_attribute

    def test_validate_all_metadata_complete(self):
        metadata = ProtectedResourceMetadata(
            {
                "resource": "https://api.example.com/v1",
                "authorization_servers": ["https://auth.example.com"],
                "jwks_uri": "https://api.example.com/.well-known/jwks.json",
                "scopes_supported": ["read", "write", "admin"],
                "bearer_methods_supported": ["header", "body"],
                "resource_signing_alg_values_supported": ["RS256", "ES256"],
                "resource_name": "Example API",
                "resource_name#fr": "API Example",
                "resource_documentation": "https://docs.example.com/api",
                "resource_documentation#fr": "https://docs.example.com/api/fr",
                "resource_policy_uri": "https://example.com/policy",
                "resource_policy_uri#fr": "https://example.com/policy/fr",
                "resource_tos_uri": "https://example.com/tos",
                "resource_tos_uri#fr": "https://example.com/tos/fr",
                "tls_client_certificate_bound_access_tokens": True,
                "authorization_details_types_supported": ["payment", "account"],
                "dpop_signing_alg_values_supported": ["RS256", "ES256"],
                "dpop_bound_access_tokens_required": False,
            }
        )
        metadata.validate()
