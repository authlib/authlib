import pytest

from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oauth2.rfc8414 import get_well_known_url

WELL_KNOWN_URL = "/.well-known/oauth-authorization-server"


def test_well_know_no_suffix_issuer():
    assert get_well_known_url("https://provider.test") == WELL_KNOWN_URL
    assert get_well_known_url("https://provider.test/") == WELL_KNOWN_URL


def test_well_know_with_suffix_issuer():
    assert (
        get_well_known_url("https://provider.test/issuer1")
        == WELL_KNOWN_URL + "/issuer1"
    )
    assert (
        get_well_known_url("https://provider.test/a/b/c") == WELL_KNOWN_URL + "/a/b/c"
    )


def test_well_know_with_external():
    assert (
        get_well_known_url("https://provider.test", external=True)
        == "https://provider.test" + WELL_KNOWN_URL
    )


def test_well_know_with_changed_suffix():
    url = get_well_known_url("https://provider.test", suffix="openid-configuration")
    assert url == "/.well-known/openid-configuration"
    url = get_well_known_url(
        "https://provider.test", external=True, suffix="openid-configuration"
    )
    assert url == "https://provider.test/.well-known/openid-configuration"


def test_validate_issuer():
    #: missing
    metadata = AuthorizationServerMetadata({})
    with pytest.raises(ValueError, match='"issuer" is required'):
        metadata.validate()

    #: https
    metadata = AuthorizationServerMetadata({"issuer": "http://provider.test/"})
    with pytest.raises(ValueError, match="https"):
        metadata.validate_issuer()

    #: query
    metadata = AuthorizationServerMetadata({"issuer": "https://provider.test/?a=b"})
    with pytest.raises(ValueError, match="query"):
        metadata.validate_issuer()

    #: fragment
    metadata = AuthorizationServerMetadata({"issuer": "https://provider.test/#a=b"})
    with pytest.raises(ValueError, match="fragment"):
        metadata.validate_issuer()

    metadata = AuthorizationServerMetadata({"issuer": "https://provider.test/"})
    metadata.validate_issuer()


def test_validate_authorization_endpoint():
    # https
    metadata = AuthorizationServerMetadata(
        {"authorization_endpoint": "http://provider.test/"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_authorization_endpoint()

    # valid https
    metadata = AuthorizationServerMetadata(
        {"authorization_endpoint": "https://provider.test/"}
    )
    metadata.validate_authorization_endpoint()

    # missing
    metadata = AuthorizationServerMetadata()
    with pytest.raises(ValueError, match="required"):
        metadata.validate_authorization_endpoint()

    # valid missing
    metadata = AuthorizationServerMetadata({"grant_types_supported": ["password"]})
    metadata.validate_authorization_endpoint()


def test_validate_token_endpoint():
    # implicit
    metadata = AuthorizationServerMetadata({"grant_types_supported": ["implicit"]})
    metadata.validate_token_endpoint()

    # missing
    metadata = AuthorizationServerMetadata()
    with pytest.raises(ValueError, match="required"):
        metadata.validate_token_endpoint()

    # https
    metadata = AuthorizationServerMetadata({"token_endpoint": "http://provider.test/"})
    with pytest.raises(ValueError, match="https"):
        metadata.validate_token_endpoint()

    # valid
    metadata = AuthorizationServerMetadata({"token_endpoint": "https://provider.test/"})
    metadata.validate_token_endpoint()


def test_validate_jwks_uri():
    # can missing
    metadata = AuthorizationServerMetadata()
    metadata.validate_jwks_uri()

    metadata = AuthorizationServerMetadata(
        {"jwks_uri": "http://provider.test/jwks.json"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_jwks_uri()

    metadata = AuthorizationServerMetadata(
        {"jwks_uri": "https://provider.test/jwks.json"}
    )
    metadata.validate_jwks_uri()


def test_validate_registration_endpoint():
    metadata = AuthorizationServerMetadata()
    metadata.validate_registration_endpoint()

    metadata = AuthorizationServerMetadata(
        {"registration_endpoint": "http://provider.test/"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_registration_endpoint()

    metadata = AuthorizationServerMetadata(
        {"registration_endpoint": "https://provider.test/"}
    )
    metadata.validate_registration_endpoint()


def test_validate_scopes_supported():
    metadata = AuthorizationServerMetadata()
    metadata.validate_scopes_supported()

    # not array
    metadata = AuthorizationServerMetadata({"scopes_supported": "foo"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_scopes_supported()

    # valid
    metadata = AuthorizationServerMetadata({"scopes_supported": ["foo"]})
    metadata.validate_scopes_supported()


def test_validate_response_types_supported():
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


def test_validate_response_modes_supported():
    metadata = AuthorizationServerMetadata()
    metadata.validate_response_modes_supported()

    # not array
    metadata = AuthorizationServerMetadata({"response_modes_supported": "query"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_response_modes_supported()

    # valid
    metadata = AuthorizationServerMetadata({"response_modes_supported": ["query"]})
    metadata.validate_response_modes_supported()


def test_validate_grant_types_supported():
    metadata = AuthorizationServerMetadata()
    metadata.validate_grant_types_supported()

    # not array
    metadata = AuthorizationServerMetadata({"grant_types_supported": "password"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_grant_types_supported()

    # valid
    metadata = AuthorizationServerMetadata({"grant_types_supported": ["password"]})
    metadata.validate_grant_types_supported()


def test_validate_token_endpoint_auth_methods_supported():
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


def test_validate_token_endpoint_auth_signing_alg_values_supported():
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


def test_validate_service_documentation():
    metadata = AuthorizationServerMetadata()
    metadata.validate_service_documentation()

    metadata = AuthorizationServerMetadata({"service_documentation": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_service_documentation()

    metadata = AuthorizationServerMetadata(
        {"service_documentation": "https://provider.test/"}
    )
    metadata.validate_service_documentation()


def test_validate_ui_locales_supported():
    metadata = AuthorizationServerMetadata()
    metadata.validate_ui_locales_supported()

    # not array
    metadata = AuthorizationServerMetadata({"ui_locales_supported": "en"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_ui_locales_supported()

    # valid
    metadata = AuthorizationServerMetadata({"ui_locales_supported": ["en"]})
    metadata.validate_ui_locales_supported()


def test_validate_op_policy_uri():
    metadata = AuthorizationServerMetadata()
    metadata.validate_op_policy_uri()

    metadata = AuthorizationServerMetadata({"op_policy_uri": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_op_policy_uri()

    metadata = AuthorizationServerMetadata({"op_policy_uri": "https://provider.test/"})
    metadata.validate_op_policy_uri()


def test_validate_op_tos_uri():
    metadata = AuthorizationServerMetadata()
    metadata.validate_op_tos_uri()

    metadata = AuthorizationServerMetadata({"op_tos_uri": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_op_tos_uri()

    metadata = AuthorizationServerMetadata({"op_tos_uri": "https://provider.test/"})
    metadata.validate_op_tos_uri()


def test_validate_revocation_endpoint():
    metadata = AuthorizationServerMetadata()
    metadata.validate_revocation_endpoint()

    # https
    metadata = AuthorizationServerMetadata(
        {"revocation_endpoint": "http://provider.test/"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_revocation_endpoint()

    # valid
    metadata = AuthorizationServerMetadata(
        {"revocation_endpoint": "https://provider.test/"}
    )
    metadata.validate_revocation_endpoint()


def test_validate_revocation_endpoint_auth_methods_supported():
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


def test_validate_revocation_endpoint_auth_signing_alg_values_supported():
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


def test_validate_introspection_endpoint():
    metadata = AuthorizationServerMetadata()
    metadata.validate_introspection_endpoint()

    # https
    metadata = AuthorizationServerMetadata(
        {"introspection_endpoint": "http://provider.test/"}
    )
    with pytest.raises(ValueError, match="https"):
        metadata.validate_introspection_endpoint()

    # valid
    metadata = AuthorizationServerMetadata(
        {"introspection_endpoint": "https://provider.test/"}
    )
    metadata.validate_introspection_endpoint()


def test_validate_introspection_endpoint_auth_methods_supported():
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


def test_validate_introspection_endpoint_auth_signing_alg_values_supported():
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


def test_validate_code_challenge_methods_supported():
    metadata = AuthorizationServerMetadata()
    metadata.validate_code_challenge_methods_supported()

    # not array
    metadata = AuthorizationServerMetadata({"code_challenge_methods_supported": "S256"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_code_challenge_methods_supported()

    # valid
    metadata = AuthorizationServerMetadata(
        {"code_challenge_methods_supported": ["S256"]}
    )
    metadata.validate_code_challenge_methods_supported()


def test_validate_with_metadata_classes():
    """Test that validate() can compose metadata extension classes."""

    base_metadata = {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/auth",
        "token_endpoint": "https://provider.test/token",
        "response_types_supported": ["code"],
    }

    metadata = AuthorizationServerMetadata(
        {**base_metadata, "require_signed_request_object": True}
    )
    metadata.validate(metadata_classes=[rfc9101.AuthorizationServerMetadata])

    metadata = AuthorizationServerMetadata(
        {**base_metadata, "require_signed_request_object": "invalid"}
    )
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[rfc9101.AuthorizationServerMetadata])
