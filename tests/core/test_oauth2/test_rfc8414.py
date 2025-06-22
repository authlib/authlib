import unittest

import pytest

from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc8414 import get_well_known_url

WELL_KNOWN_URL = "/.well-known/oauth-authorization-server"


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


class AuthorizationServerMetadataTest(unittest.TestCase):
    def test_validate_issuer(self):
        #: missing
        metadata = AuthorizationServerMetadata({})
        with pytest.raises(ValueError, match='"issuer" is required'):
            metadata.validate()

        #: https
        metadata = AuthorizationServerMetadata({"issuer": "http://authlib.org/"})
        with pytest.raises(ValueError, match="https"):
            metadata.validate_issuer()

        #: query
        metadata = AuthorizationServerMetadata({"issuer": "https://authlib.org/?a=b"})
        with pytest.raises(ValueError, match="query"):
            metadata.validate_issuer()

        #: fragment
        metadata = AuthorizationServerMetadata({"issuer": "https://authlib.org/#a=b"})
        with pytest.raises(ValueError, match="fragment"):
            metadata.validate_issuer()

        metadata = AuthorizationServerMetadata({"issuer": "https://authlib.org/"})
        metadata.validate_issuer()

    def test_validate_authorization_endpoint(self):
        # https
        metadata = AuthorizationServerMetadata(
            {"authorization_endpoint": "http://authlib.org/"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_authorization_endpoint()

        # valid https
        metadata = AuthorizationServerMetadata(
            {"authorization_endpoint": "https://authlib.org/"}
        )
        metadata.validate_authorization_endpoint()

        # missing
        metadata = AuthorizationServerMetadata()
        with pytest.raises(ValueError, match="required"):
            metadata.validate_authorization_endpoint()

        # valid missing
        metadata = AuthorizationServerMetadata({"grant_types_supported": ["password"]})
        metadata.validate_authorization_endpoint()

    def test_validate_token_endpoint(self):
        # implicit
        metadata = AuthorizationServerMetadata({"grant_types_supported": ["implicit"]})
        metadata.validate_token_endpoint()

        # missing
        metadata = AuthorizationServerMetadata()
        with pytest.raises(ValueError, match="required"):
            metadata.validate_token_endpoint()

        # https
        metadata = AuthorizationServerMetadata(
            {"token_endpoint": "http://authlib.org/"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_token_endpoint()

        # valid
        metadata = AuthorizationServerMetadata(
            {"token_endpoint": "https://authlib.org/"}
        )
        metadata.validate_token_endpoint()

    def test_validate_jwks_uri(self):
        # can missing
        metadata = AuthorizationServerMetadata()
        metadata.validate_jwks_uri()

        metadata = AuthorizationServerMetadata(
            {"jwks_uri": "http://authlib.org/jwks.json"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_jwks_uri()

        metadata = AuthorizationServerMetadata(
            {"jwks_uri": "https://authlib.org/jwks.json"}
        )
        metadata.validate_jwks_uri()

    def test_validate_registration_endpoint(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_registration_endpoint()

        metadata = AuthorizationServerMetadata(
            {"registration_endpoint": "http://authlib.org/"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_registration_endpoint()

        metadata = AuthorizationServerMetadata(
            {"registration_endpoint": "https://authlib.org/"}
        )
        metadata.validate_registration_endpoint()

    def test_validate_scopes_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_scopes_supported()

        # not array
        metadata = AuthorizationServerMetadata({"scopes_supported": "foo"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_scopes_supported()

        # valid
        metadata = AuthorizationServerMetadata({"scopes_supported": ["foo"]})
        metadata.validate_scopes_supported()

    def test_validate_response_types_supported(self):
        # missing
        metadata = AuthorizationServerMetadata()
        with pytest.raises(ValueError, match="required"):
            metadata.validate_response_types_supported()

        # not array
        metadata = AuthorizationServerMetadata({"response_types_supported": "code"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_response_types_supported()

        # valid
        metadata = AuthorizationServerMetadata({"response_types_supported": ["code"]})
        metadata.validate_response_types_supported()

    def test_validate_response_modes_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_response_modes_supported()

        # not array
        metadata = AuthorizationServerMetadata({"response_modes_supported": "query"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_response_modes_supported()

        # valid
        metadata = AuthorizationServerMetadata({"response_modes_supported": ["query"]})
        metadata.validate_response_modes_supported()

    def test_validate_grant_types_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_grant_types_supported()

        # not array
        metadata = AuthorizationServerMetadata({"grant_types_supported": "password"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_grant_types_supported()

        # valid
        metadata = AuthorizationServerMetadata({"grant_types_supported": ["password"]})
        metadata.validate_grant_types_supported()

    def test_validate_token_endpoint_auth_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_token_endpoint_auth_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_methods_supported": "client_secret_basic"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_token_endpoint_auth_methods_supported()

        # valid
        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_methods_supported": ["client_secret_basic"]}
        )
        metadata.validate_token_endpoint_auth_methods_supported()

    def test_validate_token_endpoint_auth_signing_alg_values_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_token_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_methods_supported": ["client_secret_jwt"]}
        )
        with pytest.raises(ValueError, match="required"):
            metadata.validate_token_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"token_endpoint_auth_signing_alg_values_supported": "RS256"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_token_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {
                "token_endpoint_auth_methods_supported": ["client_secret_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["RS256", "none"],
            }
        )
        with pytest.raises(ValueError, match="none"):
            metadata.validate_token_endpoint_auth_signing_alg_values_supported()

    def test_validate_service_documentation(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_service_documentation()

        metadata = AuthorizationServerMetadata({"service_documentation": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_service_documentation()

        metadata = AuthorizationServerMetadata(
            {"service_documentation": "https://authlib.org/"}
        )
        metadata.validate_service_documentation()

    def test_validate_ui_locales_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_ui_locales_supported()

        # not array
        metadata = AuthorizationServerMetadata({"ui_locales_supported": "en"})
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_ui_locales_supported()

        # valid
        metadata = AuthorizationServerMetadata({"ui_locales_supported": ["en"]})
        metadata.validate_ui_locales_supported()

    def test_validate_op_policy_uri(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_op_policy_uri()

        metadata = AuthorizationServerMetadata({"op_policy_uri": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_op_policy_uri()

        metadata = AuthorizationServerMetadata(
            {"op_policy_uri": "https://authlib.org/"}
        )
        metadata.validate_op_policy_uri()

    def test_validate_op_tos_uri(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_op_tos_uri()

        metadata = AuthorizationServerMetadata({"op_tos_uri": "invalid"})
        with pytest.raises(ValueError, match="MUST be a URL"):
            metadata.validate_op_tos_uri()

        metadata = AuthorizationServerMetadata({"op_tos_uri": "https://authlib.org/"})
        metadata.validate_op_tos_uri()

    def test_validate_revocation_endpoint(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_revocation_endpoint()

        # https
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint": "http://authlib.org/"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_revocation_endpoint()

        # valid
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint": "https://authlib.org/"}
        )
        metadata.validate_revocation_endpoint()

    def test_validate_revocation_endpoint_auth_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_revocation_endpoint_auth_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_methods_supported": "client_secret_basic"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_revocation_endpoint_auth_methods_supported()

        # valid
        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_methods_supported": ["client_secret_basic"]}
        )
        metadata.validate_revocation_endpoint_auth_methods_supported()

    def test_validate_revocation_endpoint_auth_signing_alg_values_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_methods_supported": ["client_secret_jwt"]}
        )
        with pytest.raises(ValueError, match="required"):
            metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"revocation_endpoint_auth_signing_alg_values_supported": "RS256"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {
                "revocation_endpoint_auth_methods_supported": ["client_secret_jwt"],
                "revocation_endpoint_auth_signing_alg_values_supported": [
                    "RS256",
                    "none",
                ],
            }
        )
        with pytest.raises(ValueError, match="none"):
            metadata.validate_revocation_endpoint_auth_signing_alg_values_supported()

    def test_validate_introspection_endpoint(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_introspection_endpoint()

        # https
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint": "http://authlib.org/"}
        )
        with pytest.raises(ValueError, match="https"):
            metadata.validate_introspection_endpoint()

        # valid
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint": "https://authlib.org/"}
        )
        metadata.validate_introspection_endpoint()

    def test_validate_introspection_endpoint_auth_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_introspection_endpoint_auth_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_methods_supported": "client_secret_basic"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_introspection_endpoint_auth_methods_supported()

        # valid
        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_methods_supported": ["client_secret_basic"]}
        )
        metadata.validate_introspection_endpoint_auth_methods_supported()

    def test_validate_introspection_endpoint_auth_signing_alg_values_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_methods_supported": ["client_secret_jwt"]}
        )
        with pytest.raises(ValueError, match="required"):
            metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {"introspection_endpoint_auth_signing_alg_values_supported": "RS256"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()

        metadata = AuthorizationServerMetadata(
            {
                "introspection_endpoint_auth_methods_supported": ["client_secret_jwt"],
                "introspection_endpoint_auth_signing_alg_values_supported": [
                    "RS256",
                    "none",
                ],
            }
        )
        with pytest.raises(ValueError, match="none"):
            metadata.validate_introspection_endpoint_auth_signing_alg_values_supported()

    def test_validate_code_challenge_methods_supported(self):
        metadata = AuthorizationServerMetadata()
        metadata.validate_code_challenge_methods_supported()

        # not array
        metadata = AuthorizationServerMetadata(
            {"code_challenge_methods_supported": "S256"}
        )
        with pytest.raises(ValueError, match="JSON array"):
            metadata.validate_code_challenge_methods_supported()

        # valid
        metadata = AuthorizationServerMetadata(
            {"code_challenge_methods_supported": ["S256"]}
        )
        metadata.validate_code_challenge_methods_supported()
