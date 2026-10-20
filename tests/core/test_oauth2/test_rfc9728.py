import pytest
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey
from joserfc.jwk import OKPKey
from joserfc.jwk import RSAKey

from authlib.oauth2 import rfc8414
from authlib.oauth2 import rfc9728
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from authlib.oauth2.rfc6749.errors import MissingAuthorizationError
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc9728 import ProtectedResourceMetadata
from authlib.oauth2.rfc9728 import ResourceMetadataExtension
from authlib.oauth2.rfc9728.well_known import get_well_known_url

WELL_KNOWN_URL = "/.well-known/oauth-protected-resource"


def test_well_known_without_path():
    """A resource identifier without path gives the bare well-known path."""
    assert get_well_known_url("https://resource.test") == WELL_KNOWN_URL
    assert get_well_known_url("https://resource.test/") == WELL_KNOWN_URL


def test_well_known_with_path():
    """The path of the resource identifier goes after the well-known path."""
    assert (
        get_well_known_url("https://resource.test/issuer1")
        == WELL_KNOWN_URL + "/issuer1"
    )
    assert (
        get_well_known_url("https://resource.test/a/b/c") == WELL_KNOWN_URL + "/a/b/c"
    )


def test_well_known_with_external():
    """external=True returns the full URL."""
    assert (
        get_well_known_url("https://resource.test", external=True)
        == "https://resource.test" + WELL_KNOWN_URL
    )


def test_well_known_with_trailing_slash():
    """A trailing slash in the path is kept."""
    assert get_well_known_url("https://resource.test/api/") == WELL_KNOWN_URL + "/api/"


def test_well_known_external_with_path():
    """external=True keeps the path after the well-known path."""
    assert (
        get_well_known_url("https://resource.test/api", external=True)
        == "https://resource.test" + WELL_KNOWN_URL + "/api"
    )


def test_well_known_with_query():
    """The query is kept in the full URL, and dropped from the relative path."""
    assert get_well_known_url("https://resource.test/api?v=1") == (
        WELL_KNOWN_URL + "/api"
    )
    assert get_well_known_url("https://resource.test/api?v=1", external=True) == (
        "https://resource.test" + WELL_KNOWN_URL + "/api?v=1"
    )


def test_well_known_with_changed_suffix():
    """The well-known suffix can be changed."""
    url = get_well_known_url("https://resource.test", suffix="openid-configuration")
    assert url == "/.well-known/openid-configuration"
    url = get_well_known_url(
        "https://resource.test", external=True, suffix="openid-configuration"
    )
    assert url == "https://resource.test/.well-known/openid-configuration"


def test_validate_resource():
    """resource is required, uses https and has no fragment."""
    metadata = ProtectedResourceMetadata({})
    with pytest.raises(ValueError, match='"resource" is required'):
        metadata.validate()

    metadata = ProtectedResourceMetadata({"resource": "http://resource.test/api"})
    with pytest.raises(ValueError, match="https"):
        metadata.validate_resource()

    metadata = ProtectedResourceMetadata(
        {"resource": "https://resource.test/api#fragment"}
    )
    with pytest.raises(ValueError, match="fragment"):
        metadata.validate_resource()

    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api#"})
    with pytest.raises(ValueError, match="fragment"):
        metadata.validate_resource()

    metadata = ProtectedResourceMetadata({"resource": 123})
    with pytest.raises(ValueError, match="MUST be a string"):
        metadata.validate_resource()

    for uri in ["http://localhost/api", "http://127.0.0.1/api"]:
        metadata = ProtectedResourceMetadata({"resource": uri})
        with pytest.raises(ValueError, match="https"):
            metadata.validate_resource()

    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.validate_resource()


def test_validate_authorization_servers():
    """authorization_servers must be a JSON array."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_authorization_servers()

    metadata = ProtectedResourceMetadata(
        {"authorization_servers": "https://auth.test/"}
    )
    with pytest.raises(ValueError, match="MUST be JSON array"):
        metadata.validate_authorization_servers()

    metadata = ProtectedResourceMetadata(
        {"authorization_servers": ["https://auth.test/"]}
    )
    metadata.validate_authorization_servers()


def test_validate_jwks_uri():
    """jwks_uri must use https."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_jwks_uri()

    metadata = ProtectedResourceMetadata({"jwks_uri": "http://resource.test/jwks.json"})
    with pytest.raises(ValueError, match="https"):
        metadata.validate_jwks_uri()

    metadata = ProtectedResourceMetadata({"jwks_uri": "http://localhost/jwks.json"})
    with pytest.raises(ValueError, match="https"):
        metadata.validate_jwks_uri()

    metadata = ProtectedResourceMetadata(
        {"jwks_uri": "https://resource.test/jwks.json"}
    )
    metadata.validate_jwks_uri()


def test_validate_scopes_supported():
    """scopes_supported must be a JSON array."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_scopes_supported()

    metadata = ProtectedResourceMetadata({"scopes_supported": "foo"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_scopes_supported()

    metadata = ProtectedResourceMetadata({"scopes_supported": ["foo"]})
    metadata.validate_scopes_supported()


@pytest.mark.parametrize(
    "key",
    [
        "authorization_servers",
        "scopes_supported",
        "resource_signing_alg_values_supported",
        "authorization_details_types_supported",
        "dpop_signing_alg_values_supported",
    ],
)
def test_validate_empty_array(key):
    """Empty arrays are rejected, because they must be omitted (Section 3.2)."""
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test", key: []})
    with pytest.raises(ValueError, match="MUST be omitted when empty"):
        metadata.validate()


def test_validate_bearer_methods_supported():
    """bearer_methods_supported only accepts header, body and query, and may be empty."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_bearer_methods_supported()

    metadata = ProtectedResourceMetadata({"bearer_methods_supported": "foo"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_bearer_methods_supported()

    metadata = ProtectedResourceMetadata({"bearer_methods_supported": ["foo"]})
    with pytest.raises(ValueError, match="method"):
        metadata.validate_bearer_methods_supported()

    metadata = ProtectedResourceMetadata({"bearer_methods_supported": []})
    metadata.validate_bearer_methods_supported()

    metadata = ProtectedResourceMetadata(
        {"bearer_methods_supported": ["header", "body", "query"]}
    )
    metadata.validate_bearer_methods_supported()


def test_validate_resource_signing_alg_values_supported():
    """resource_signing_alg_values_supported must be a JSON array without none."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_resource_signing_alg_values_supported()

    metadata = ProtectedResourceMetadata(
        {"resource_signing_alg_values_supported": "foo"}
    )
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_resource_signing_alg_values_supported()

    metadata = ProtectedResourceMetadata(
        {"resource_signing_alg_values_supported": ["none"]}
    )
    with pytest.raises(ValueError, match="none"):
        metadata.validate_resource_signing_alg_values_supported()

    metadata = ProtectedResourceMetadata(
        {"resource_signing_alg_values_supported": ["RS256", "ES256"]}
    )
    metadata.validate_resource_signing_alg_values_supported()


def test_validate_resource_name():
    """resource_name and its localized variants must be strings."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_resource_name()

    metadata = ProtectedResourceMetadata({"resource_name": 123})
    with pytest.raises(ValueError, match="MUST be a string"):
        metadata.validate_resource_name()

    metadata = ProtectedResourceMetadata({"resource_name": "My Resource API"})
    metadata.validate_resource_name()

    metadata = ProtectedResourceMetadata({"resource_name#en": 123})
    with pytest.raises(ValueError, match="MUST be a string"):
        metadata.validate_resource_name()

    metadata = ProtectedResourceMetadata({"resource_name#fr": "Mon API Resource"})
    metadata.validate_resource_name()


def test_validate_resource_documentation():
    """resource_documentation and its localized variants must be URLs."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_resource_documentation()

    metadata = ProtectedResourceMetadata({"resource_documentation": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_documentation()

    metadata = ProtectedResourceMetadata(
        {"resource_documentation": "http//resource.test/docs"}
    )
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_documentation()

    metadata = ProtectedResourceMetadata(
        {"resource_documentation": "https://resource.test/docs"}
    )
    metadata.validate_resource_documentation()

    metadata = ProtectedResourceMetadata({"resource_documentation#fr": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_documentation()

    metadata = ProtectedResourceMetadata(
        {"resource_documentation#fr": "https://resource.test/docs/fr"}
    )
    metadata.validate_resource_documentation()


def test_validate_resource_policy_uri():
    """resource_policy_uri must be a URL."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_resource_policy_uri()

    metadata = ProtectedResourceMetadata({"resource_policy_uri": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_policy_uri()

    metadata = ProtectedResourceMetadata(
        {"resource_policy_uri": "https://resource.test/policy"}
    )
    metadata.validate_resource_policy_uri()


def test_validate_resource_tos_uri():
    """resource_tos_uri must be a URL."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_resource_tos_uri()

    metadata = ProtectedResourceMetadata({"resource_tos_uri": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_tos_uri()

    metadata = ProtectedResourceMetadata(
        {"resource_tos_uri": "https://resource.test/tos"}
    )
    metadata.validate_resource_tos_uri()


def test_validate_tls_client_certificate_bound_access_tokens():
    """tls_client_certificate_bound_access_tokens must be a boolean."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_tls_client_certificate_bound_access_tokens()

    metadata = ProtectedResourceMetadata(
        {"tls_client_certificate_bound_access_tokens": "invalid"}
    )
    with pytest.raises(ValueError, match="MUST be a boolean"):
        metadata.validate_tls_client_certificate_bound_access_tokens()

    metadata = ProtectedResourceMetadata(
        {"tls_client_certificate_bound_access_tokens": True}
    )
    metadata.validate_tls_client_certificate_bound_access_tokens()

    metadata = ProtectedResourceMetadata(
        {"tls_client_certificate_bound_access_tokens": False}
    )
    metadata.validate_tls_client_certificate_bound_access_tokens()

    metadata = ProtectedResourceMetadata(
        {"tls_client_certificate_bound_access_tokens": 0}
    )
    with pytest.raises(ValueError, match="MUST be a boolean"):
        metadata.validate_tls_client_certificate_bound_access_tokens()


def test_validate_authorization_details_types_supported():
    """authorization_details_types_supported must be a JSON array."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_authorization_details_types_supported()

    metadata = ProtectedResourceMetadata(
        {"authorization_details_types_supported": "foo"}
    )
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_authorization_details_types_supported()

    metadata = ProtectedResourceMetadata(
        {"authorization_details_types_supported": ["foo"]}
    )
    metadata.validate_authorization_details_types_supported()


def test_validate_dpop_signing_alg_values_supported():
    """dpop_signing_alg_values_supported must be a JSON array without none."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_dpop_signing_alg_values_supported()

    metadata = ProtectedResourceMetadata({"dpop_signing_alg_values_supported": "foo"})
    with pytest.raises(ValueError, match="JSON array"):
        metadata.validate_dpop_signing_alg_values_supported()

    metadata = ProtectedResourceMetadata(
        {"dpop_signing_alg_values_supported": ["none"]}
    )
    with pytest.raises(ValueError, match='"none" MUST NOT be used'):
        metadata.validate_dpop_signing_alg_values_supported()

    metadata = ProtectedResourceMetadata(
        {"dpop_signing_alg_values_supported": ["RS256", "ES256"]}
    )
    metadata.validate_dpop_signing_alg_values_supported()


def test_validate_dpop_bound_access_tokens_required():
    """dpop_bound_access_tokens_required must be a boolean."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_dpop_bound_access_tokens_required()

    metadata = ProtectedResourceMetadata({"dpop_bound_access_tokens_required": "foo"})
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate_dpop_bound_access_tokens_required()

    metadata = ProtectedResourceMetadata({"dpop_bound_access_tokens_required": True})
    metadata.validate_dpop_bound_access_tokens_required()

    metadata = ProtectedResourceMetadata({"dpop_bound_access_tokens_required": False})
    metadata.validate_dpop_bound_access_tokens_required()

    metadata = ProtectedResourceMetadata({"dpop_bound_access_tokens_required": 0})
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate_dpop_bound_access_tokens_required()


def test_validate_resource_policy_uri_internationalized():
    """Localized resource_policy_uri variants must be URLs."""
    metadata = ProtectedResourceMetadata({"resource_policy_uri#es": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_policy_uri()

    metadata = ProtectedResourceMetadata(
        {"resource_policy_uri#es": "https://resource.test/policy/es"}
    )
    metadata.validate_resource_policy_uri()


def test_validate_resource_tos_uri_internationalized():
    """Localized resource_tos_uri variants must be URLs."""
    metadata = ProtectedResourceMetadata({"resource_tos_uri#de": "invalid"})
    with pytest.raises(ValueError, match="MUST be a URL"):
        metadata.validate_resource_tos_uri()

    metadata = ProtectedResourceMetadata(
        {"resource_tos_uri#de": "https://resource.test/tos/de"}
    )
    metadata.validate_resource_tos_uri()


def test_properties_default_values():
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


def test_getattr_registry_keys():
    """Metadata keys can be read as attributes, and missing keys give None."""
    metadata = ProtectedResourceMetadata(
        {
            "resource": "https://resource.test/api",
            "scopes_supported": ["read", "write"],
        }
    )

    assert metadata.resource == "https://resource.test/api"
    assert metadata.scopes_supported == ["read", "write"]
    assert metadata.authorization_servers is None


def test_getattr_non_registry_keys():
    """Unknown attributes raise AttributeError."""
    metadata = ProtectedResourceMetadata({})

    with pytest.raises(AttributeError):
        _ = metadata.non_existent_attribute


def test_sign_metadata():
    """sign_metadata produces a JWT with all claims, iss defaulting to resource."""
    key = OctKey.generate_key(256)
    metadata = ProtectedResourceMetadata(
        {
            "resource": "https://resource.test/api",
            "scopes_supported": ["read", "write"],
        }
    )
    token = metadata.sign_metadata(key, "HS256")

    assert isinstance(token, str)
    assert metadata["signed_metadata"] == token

    decoded = jwt.decode(token, key)
    assert decoded.claims["iss"] == "https://resource.test/api"
    assert decoded.claims["resource"] == "https://resource.test/api"
    assert decoded.claims["scopes_supported"] == ["read", "write"]
    assert "signed_metadata" not in decoded.claims


def test_sign_metadata_custom_issuer():
    """A third party can sign on behalf of the resource (Section 2.2)."""
    key = OctKey.generate_key(256)
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key, "HS256", issuer="https://auth.test")

    decoded = jwt.decode(metadata["signed_metadata"], key)
    assert decoded.claims["iss"] == "https://auth.test"


def test_sign_metadata_auto_algorithm_oct():
    """Algorithm is guessed as HS256 for OctKey."""
    key = OctKey.generate_key(256)
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key)
    decoded = jwt.decode(metadata["signed_metadata"], key)
    assert decoded.header["alg"] == "HS256"


def test_sign_metadata_auto_algorithm_rsa():
    """Algorithm is guessed as RS256 for RSAKey."""
    key = RSAKey.generate_key(2048)
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key)
    decoded = jwt.decode(metadata["signed_metadata"], key)
    assert decoded.header["alg"] == "RS256"


def test_sign_metadata_auto_algorithm_ec():
    """Algorithm is guessed as ES256 for ECKey P-256."""
    key = ECKey.generate_key("P-256")
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key)
    decoded = jwt.decode(metadata["signed_metadata"], key)
    assert decoded.header["alg"] == "ES256"


def test_sign_metadata_auto_algorithm_unsupported():
    """OKP keys have no recommended algorithm, explicit algorithm required."""
    key = OKPKey.generate_key("Ed25519")
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    with pytest.raises(ValueError, match="Cannot determine algorithm"):
        metadata.sign_metadata(key)


def test_sign_metadata_explicit_algorithm():
    """An explicit algorithm is used even if joserfc does not recommend it."""
    key = RSAKey.generate_key(2048)
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key, algorithm="RS512")
    decoded = jwt.decode(metadata["signed_metadata"], key, algorithms=["RS512"])
    assert decoded.header["alg"] == "RS512"


def test_sign_metadata_explicit_algorithm_okp():
    """OKP keys can sign with an explicit algorithm."""
    key = OKPKey.generate_key("Ed25519")
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key, algorithm="Ed25519")
    decoded = jwt.decode(metadata["signed_metadata"], key, algorithms=["Ed25519"])
    assert decoded.header["alg"] == "Ed25519"


def test_validate_all_metadata_complete():
    """Metadata with all the fields is valid."""
    metadata = ProtectedResourceMetadata(
        {
            "resource": "https://resource.test/api/v1",
            "authorization_servers": ["https://auth.test"],
            "jwks_uri": "https://resource.test/.well-known/jwks.json",
            "scopes_supported": ["read", "write", "admin"],
            "bearer_methods_supported": ["header", "body"],
            "resource_signing_alg_values_supported": ["RS256", "ES256"],
            "resource_name": "Example API",
            "resource_name#fr": "API Example",
            "resource_documentation": "https://resource.test/docs",
            "resource_documentation#fr": "https://resource.test/docs/fr",
            "resource_policy_uri": "https://resource.test/policy",
            "resource_policy_uri#fr": "https://resource.test/policy/fr",
            "resource_tos_uri": "https://resource.test/tos",
            "resource_tos_uri#fr": "https://resource.test/tos/fr",
            "tls_client_certificate_bound_access_tokens": True,
            "authorization_details_types_supported": ["payment", "account"],
            "dpop_signing_alg_values_supported": ["RS256", "ES256"],
            "dpop_bound_access_tokens_required": False,
        }
    )
    metadata.validate()


def test_validate_protected_resources():
    """protected_resources is an optional JSON array (Section 4)."""
    metadata = rfc9728.AuthorizationServerMetadata()
    metadata.validate_protected_resources()

    metadata = rfc9728.AuthorizationServerMetadata(
        {"protected_resources": ["https://resource.test/api"]}
    )
    metadata.validate_protected_resources()

    metadata = rfc9728.AuthorizationServerMetadata(
        {"protected_resources": "https://resource.test/api"}
    )
    with pytest.raises(ValueError, match="MUST be JSON array"):
        metadata.validate_protected_resources()


def test_protected_resources_metadata_classes_composition():
    """protected_resources can be validated via metadata_classes on rfc8414."""
    base_metadata = {
        "issuer": "https://auth.test",
        "authorization_endpoint": "https://auth.test/authorize",
        "token_endpoint": "https://auth.test/token",
        "response_types_supported": ["code"],
    }

    metadata = rfc8414.AuthorizationServerMetadata(
        {**base_metadata, "protected_resources": ["https://resource.test/api"]}
    )
    metadata.validate(metadata_classes=[rfc9728.AuthorizationServerMetadata])

    metadata = rfc8414.AuthorizationServerMetadata(
        {**base_metadata, "protected_resources": "https://resource.test/api"}
    )
    with pytest.raises(ValueError, match="MUST be JSON array"):
        metadata.validate(metadata_classes=[rfc9728.AuthorizationServerMetadata])


RESOURCE_METADATA_URL = "https://resource.test/.well-known/oauth-protected-resource"


def test_resource_metadata_extension():
    """ResourceMetadataExtension injects resource_metadata into WWW-Authenticate."""

    class FakeRequest:
        headers = {}

    metadata = ProtectedResourceMetadata({"resource": "https://resource.test"})
    protector = ResourceProtector()
    protector.register_extension(ResourceMetadataExtension(metadata))

    class FakeValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return None

    protector.register_token_validator(FakeValidator())

    with pytest.raises(MissingAuthorizationError) as exc_info:
        protector.validate_request(scopes=None, request=FakeRequest())

    headers = dict(exc_info.value.get_headers())
    assert f'resource_metadata="{RESOURCE_METADATA_URL}"' in headers["WWW-Authenticate"]


def test_resource_metadata_extension_skips_non_auth_errors():
    """ResourceMetadataExtension does not inject WWW-Authenticate on 400 errors."""

    class FakeRequest:
        headers = {"Authorization": "Bearer token"}

    metadata = ProtectedResourceMetadata({"resource": "https://resource.test"})
    protector = ResourceProtector()
    protector.register_extension(ResourceMetadataExtension(metadata))

    class FakeValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return None

        def validate_token(self, token, scopes, request, **kwargs):
            raise InvalidRequestError()

    protector.register_token_validator(FakeValidator())

    with pytest.raises(InvalidRequestError) as exc_info:
        protector.validate_request(scopes=None, request=FakeRequest())

    headers = dict(exc_info.value.get_headers())
    assert "WWW-Authenticate" not in headers


def test_resource_metadata_extension_insufficient_scope():
    """ResourceMetadataExtension injects a WWW-Authenticate on 403 even when absent."""

    class FakeRequest:
        headers = {"Authorization": "Bearer token"}

    metadata = ProtectedResourceMetadata({"resource": "https://resource.test"})
    protector = ResourceProtector()
    protector.register_extension(ResourceMetadataExtension(metadata))

    class FakeValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return None

        def validate_token(self, token, scopes, request, **kwargs):
            raise InsufficientScopeError()

    protector.register_token_validator(FakeValidator())

    with pytest.raises(InsufficientScopeError) as exc_info:
        protector.validate_request(scopes=["read"], request=FakeRequest())

    headers = dict(exc_info.value.get_headers())
    assert f'resource_metadata="{RESOURCE_METADATA_URL}"' in headers["WWW-Authenticate"]
    assert headers["WWW-Authenticate"].startswith("bearer ")


def test_sign_metadata_skips_existing_signed_metadata():
    """sign_metadata excludes pre-existing signed_metadata from the JWT claims."""
    key = OctKey.generate_key(256)
    metadata = ProtectedResourceMetadata({"resource": "https://resource.test/api"})
    metadata.sign_metadata(key, "HS256")

    metadata.sign_metadata(key, "HS256")
    decoded = jwt.decode(metadata["signed_metadata"], key)
    assert "signed_metadata" not in decoded.claims


def test_validate_signed_metadata():
    """signed_metadata is optional and must be a string."""
    metadata = ProtectedResourceMetadata()
    metadata.validate_signed_metadata()

    metadata = ProtectedResourceMetadata({"signed_metadata": 123})
    with pytest.raises(ValueError, match="MUST be a string"):
        metadata.validate_signed_metadata()

    metadata = ProtectedResourceMetadata({"signed_metadata": "a.b.c"})
    metadata.validate_signed_metadata()


def test_signed_metadata_attribute_access():
    """signed_metadata is accessible as an attribute via REGISTRY_KEYS."""
    metadata = ProtectedResourceMetadata({"signed_metadata": "a.b.c"})
    assert metadata.signed_metadata == "a.b.c"

    metadata = ProtectedResourceMetadata()
    assert metadata.signed_metadata is None
