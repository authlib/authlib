import unittest

import pytest

from authlib.oidc.discovery import OpenIDProviderMetadata
from authlib.oidc.discovery import get_well_known_url

WELL_KNOWN_URL = "/.well-known/openid-configuration"


class WellKnownTest(unittest.TestCase):
    def test_no_suffix_issuer(self):
        assert get_well_known_url("https://authlib.org") == WELL_KNOWN_URL
        assert get_well_known_url("https://authlib.org/") == WELL_KNOWN_URL

    def test_with_suffix_issuer(self):
        assert (
            get_well_known_url("https://authlib.org/issuer1")
            == "/issuer1" + WELL_KNOWN_URL
        )
        assert (
            get_well_known_url("https://authlib.org/a/b/c") == "/a/b/c" + WELL_KNOWN_URL
        )

    def test_with_external(self):
        assert (
            get_well_known_url("https://authlib.org", external=True)
            == "https://authlib.org" + WELL_KNOWN_URL
        )


class OpenIDProviderMetadataTest(unittest.TestCase):
    def test_validate_jwks_uri(self):
        # required
        metadata = OpenIDProviderMetadata()
        with pytest.raises(ValueError, match='"jwks_uri" is required'):
            metadata.validate_jwks_uri()

        metadata = OpenIDProviderMetadata({"jwks_uri": "http://authlib.org/jwks.json"})
        with pytest.raises(ValueError, match="https"):
            metadata.validate_jwks_uri()

        metadata = OpenIDProviderMetadata({"jwks_uri": "https://authlib.org/jwks.json"})
        metadata.validate_jwks_uri()

    def test_validate_acr_values_supported(self):
        self._call_validate_array(
            "acr_values_supported", ["urn:mace:incommon:iap:silver"]
        )

    def test_validate_subject_types_supported(self):
        self._call_validate_array(
            "subject_types_supported", ["pairwise", "public"], required=True
        )
        self._call_contains_invalid_value("subject_types_supported", ["invalid"])

    def test_validate_id_token_signing_alg_values_supported(self):
        self._call_validate_array(
            "id_token_signing_alg_values_supported",
            ["RS256"],
            required=True,
        )
        metadata = OpenIDProviderMetadata(
            {"id_token_signing_alg_values_supported": ["none"]}
        )
        with pytest.raises(ValueError, match="RS256"):
            metadata.validate_id_token_signing_alg_values_supported()

    def test_validate_id_token_encryption_alg_values_supported(self):
        self._call_validate_array(
            "id_token_encryption_alg_values_supported", ["A128KW"]
        )

    def test_validate_id_token_encryption_enc_values_supported(self):
        self._call_validate_array(
            "id_token_encryption_enc_values_supported", ["A128GCM"]
        )

    def test_validate_userinfo_signing_alg_values_supported(self):
        self._call_validate_array("userinfo_signing_alg_values_supported", ["RS256"])

    def test_validate_userinfo_encryption_alg_values_supported(self):
        self._call_validate_array(
            "userinfo_encryption_alg_values_supported", ["A128KW"]
        )

    def test_validate_userinfo_encryption_enc_values_supported(self):
        self._call_validate_array(
            "userinfo_encryption_enc_values_supported", ["A128GCM"]
        )

    def test_validate_request_object_signing_alg_values_supported(self):
        self._call_validate_array(
            "request_object_signing_alg_values_supported", ["none", "RS256"]
        )

    def test_validate_request_object_encryption_alg_values_supported(self):
        self._call_validate_array(
            "request_object_encryption_alg_values_supported", ["A128KW"]
        )

    def test_validate_request_object_encryption_enc_values_supported(self):
        self._call_validate_array(
            "request_object_encryption_enc_values_supported", ["A128GCM"]
        )

    def test_validate_display_values_supported(self):
        self._call_validate_array("display_values_supported", ["page", "touch"])
        self._call_contains_invalid_value("display_values_supported", ["invalid"])

    def test_validate_claim_types_supported(self):
        self._call_validate_array("claim_types_supported", ["normal"])
        self._call_contains_invalid_value("claim_types_supported", ["invalid"])
        metadata = OpenIDProviderMetadata()
        assert metadata.claim_types_supported == ["normal"]

    def test_validate_claims_supported(self):
        self._call_validate_array("claims_supported", ["sub"])

    def test_validate_claims_locales_supported(self):
        self._call_validate_array("claims_locales_supported", ["en-US"])

    def test_validate_claims_parameter_supported(self):
        self._call_validate_boolean("claims_parameter_supported")

    def test_validate_request_parameter_supported(self):
        self._call_validate_boolean("request_parameter_supported")

    def test_validate_request_uri_parameter_supported(self):
        self._call_validate_boolean("request_uri_parameter_supported", True)

    def test_validate_require_request_uri_registration(self):
        self._call_validate_boolean("require_request_uri_registration")

    def _call_validate_boolean(self, key, default_value=False):
        def _validate(metadata):
            getattr(metadata, "validate_" + key)()

        metadata = OpenIDProviderMetadata()
        _validate(metadata)
        assert getattr(metadata, key) == default_value

        metadata = OpenIDProviderMetadata({key: "str"})
        with pytest.raises(ValueError, match="MUST be boolean"):
            _validate(metadata)

        metadata = OpenIDProviderMetadata({key: True})
        _validate(metadata)

    def _call_validate_array(self, key, valid_value, required=False):
        def _validate(metadata):
            getattr(metadata, "validate_" + key)()

        metadata = OpenIDProviderMetadata()
        if required:
            with pytest.raises(ValueError, match=f'"{key}" is required'):
                _validate(metadata)

        else:
            _validate(metadata)

        # not array
        metadata = OpenIDProviderMetadata({key: "foo"})
        with pytest.raises(ValueError, match="JSON array"):
            _validate(metadata)

        # valid
        metadata = OpenIDProviderMetadata({key: valid_value})
        _validate(metadata)

    def _call_contains_invalid_value(self, key, invalid_value):
        metadata = OpenIDProviderMetadata({key: invalid_value})
        with pytest.raises(ValueError, match=f'"{key}" contains invalid values'):
            getattr(metadata, "validate_" + key)()
