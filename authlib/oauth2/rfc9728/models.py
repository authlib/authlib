"""Support for OAuth 2.0 Protected Resource Metadata model validation"""

from joserfc import jwt
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import is_secure_transport
from authlib.common.urls import is_valid_url
from authlib.oauth2.rfc8414.models import validate_array_value

from .well_known import get_well_known_url


class ProtectedResourceMetadata(dict):
    """Define Protected Resource Metadata per :rfc:`9728#section-2`.

    A ``dict`` subclass with validation for all metadata fields defined by the
    specification. Fields are accessed as dict keys or as attributes::

        from authlib.oauth2.rfc9728 import ProtectedResourceMetadata

        metadata = ProtectedResourceMetadata(
            {
                "resource": "https://api.example.com/",
                "authorization_servers": ["https://auth.example.com"],
                "jwks_uri": "https://api.example.com/.well-known/jwks.json",
                "scopes_supported": ["read", "write", "admin"],
                "bearer_methods_supported": ["header"],
                "resource_signing_alg_values_supported": ["RS256", "ES256"],
                "resource_name": "Example API",
                "resource_name#fr": "API Example",
                "resource_documentation": "https://api.example.com/docs",
                "resource_policy_uri": "https://example.com/policy",
                "resource_tos_uri": "https://example.com/tos",
            }
        )
        metadata.validate()
    """

    REGISTRY_KEYS = [
        "resource",
        "authorization_servers",
        "jwks_uri",
        "scopes_supported",
        "bearer_methods_supported",
        "resource_signing_alg_values_supported",
        "resource_name",
        "resource_documentation",
        "resource_policy_uri",
        "resource_tos_uri",
        "tls_client_certificate_bound_access_tokens",
        "authorization_details_types_supported",
        "dpop_signing_alg_values_supported",
        "dpop_bound_access_tokens_required",
        "signed_metadata",
    ]

    def validate_resource(self):
        """The protected resource's resource identifier as defined in
        Section 1.2 of RFC9728.
        """
        resource = self.get("resource")
        if not resource:
            raise ValueError('"resource" is required')

        if not isinstance(resource, str):
            raise ValueError('"resource" MUST be a string')

        # rfc9728 §1.2: "Resource Identifier: The protected resource's
        # resource identifier, which is a URL that uses the https scheme and
        # has no fragment component."
        if not is_secure_transport(resource, allow_loopback=False):
            raise ValueError('"resource" MUST use "https" scheme')

        if "#" in resource:
            raise ValueError('"resource" MUST NOT contain a fragment')

    def validate_authorization_servers(self):
        """JSON array containing a list of OAuth authorization server
        issuer identifiers, as defined in [RFC8414].
        """
        _validate_non_empty_array(self, "authorization_servers")

    def validate_jwks_uri(self):
        """URL of the protected resource's JSON Web Key (JWK) Set
        [JWK] document. This contains public keys belonging to the protected
        resource, such as signing key(s) that the resource server uses to sign
        resource responses. This URL MUST use the https scheme. When both
        signing and encryption keys are made available, a use (public key use)
        parameter value is REQUIRED for all keys in the referenced JWK Set to
        indicate each key's intended usage.

        """
        url = self.get("jwks_uri")
        if url is None:
            return

        if not isinstance(url, str):
            raise ValueError('"jwks_uri" MUST be a string')

        if not is_secure_transport(url, allow_loopback=False):
            raise ValueError('"jwks_uri" MUST use "https" scheme')

    def validate_scopes_supported(self):
        """JSON array containing a list of scope values, as
        defined in OAuth 2.0 [RFC6749], that are used in authorization
        requests to request access to this protected resource. Protected
        resources MAY choose not to advertise some scope values supported
        even when this parameter is used.
        """
        _validate_non_empty_array(self, "scopes_supported")

    def validate_bearer_methods_supported(self):
        """JSON array containing a list of the supported methods of
        sending an OAuth 2.0 bearer token [RFC6750] to the protected resource.
        Defined values are ["header", "body", "query"], corresponding to
        Sections 2.1, 2.2, and 2.3 of [RFC6750]. The empty array [] can be used
        to indicate that no bearer methods are supported. If this entry is
        omitted, no default bearer methods supported are implied, nor does its
        absence indicate that they are not supported.
        """
        validate_array_value(self, "bearer_methods_supported")
        for method in self.get("bearer_methods_supported", []):
            if method not in ["header", "body", "query"]:
                raise ValueError(
                    f'"{method}" is not a valid bearer method, valid methods are: '
                    "header, body, query"
                )

    def validate_resource_signing_alg_values_supported(self):
        """JSON array containing a list of the JWS [JWS] signing
        algorithms (alg values) [JWA] supported by the protected resource for
        signing resource responses, for instance, as described in
        [FAPI.MessageSigning]. No default algorithms are implied if this entry
        is omitted. The value none MUST NOT be used.
        """
        _validate_non_empty_array(self, "resource_signing_alg_values_supported")
        value = self.get("resource_signing_alg_values_supported")

        if value and "none" in value:
            raise ValueError(
                'the value "none" MUST NOT be used in '
                '"resource_signing_alg_values_supported"'
            )

    def validate_resource_name(self):
        """Human-readable name of the protected resource intended for display
        to the end user. It is RECOMMENDED that protected resource metadata
        include this field. The value of this field MAY be internationalized,
        as described in Section 2.1.
        """
        # rfc9728 §2.1: "To specify the languages and scripts, language tags
        # [BCP47] are added to resource metadata parameter names, delimited
        # by a # character."
        _validate_localized_string(self, "resource_name")

    def validate_resource_documentation(self):
        """URL of a page containing human-readable information that
        developers might want or need to know when using the protected
        resource. The value of this field MAY be internationalized, as
        described in Section 2.1.
        """
        _validate_localized_url(self, "resource_documentation")

    def validate_resource_policy_uri(self):
        """URL of a page containing human-readable information about
        the protected resource's requirements on how the client can use the
        data provided by the protected resource. The value of this field MAY be
        internationalized, as described in Section 2.1.

        """
        _validate_localized_url(self, "resource_policy_uri")

    def validate_resource_tos_uri(self):
        """URL of a page containing human-readable information about
        the protected resource's terms of service. The value of this field MAY
        be internationalized, as described in Section 2.1.
        """
        _validate_localized_url(self, "resource_tos_uri")

    def validate_tls_client_certificate_bound_access_tokens(self):
        """Boolean value indicating protected resource support for
        mutual-TLS client certificate-bound access tokens [RFC8705]. If
        omitted, the default value is false.
        """
        value = self.get("tls_client_certificate_bound_access_tokens")
        if value is not None and not isinstance(value, bool):
            raise ValueError(
                '"tls_client_certificate_bound_access_tokens" MUST be a boolean'
            )

    def validate_authorization_details_types_supported(self):
        """JSON array containing a list of the authorization details type
        values supported by the resource server when the authorization_details
        request parameter [RFC9396] is used.
        """
        _validate_non_empty_array(self, "authorization_details_types_supported")

    def validate_dpop_signing_alg_values_supported(self):
        """JSON array containing a list of the JWS alg values (from the
        "JSON Web Signature and Encryption Algorithms" registry [IANA.JOSE])
        supported by the resource server for validating
        Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449].

        """
        _validate_non_empty_array(self, "dpop_signing_alg_values_supported")
        value = self.get("dpop_signing_alg_values_supported")
        if value and "none" in value:
            raise ValueError(
                'the value "none" MUST NOT be used in "dpop_signing_alg_values_supported"'
            )

    def validate_dpop_bound_access_tokens_required(self):
        """Boolean value specifying whether the protected resource
        always requires the use of DPoP-bound access tokens [RFC9449].
        If omitted, the default value is false.

        """
        value = self.get("dpop_bound_access_tokens_required")
        if value is not None and not isinstance(value, bool):
            raise ValueError('"dpop_bound_access_tokens_required" MUST be a boolean')

    def validate_signed_metadata(self):
        """JWT containing metadata values as claims per :rfc:`9728#section-2.2`."""
        value = self.get("signed_metadata")
        if value is not None and not isinstance(value, str):
            raise ValueError('"signed_metadata" MUST be a string')

    def sign_metadata(self, key, algorithm=None, issuer=None):
        """Sign the metadata as a JWT and store it in ``self["signed_metadata"]``.

        Returns the signed JWT string. The algorithm is automatically selected
        based on the key type (e.g. RS256 for RSA, ES256 for EC P-256). Pass
        ``algorithm`` explicitly to override. The ``iss`` claim defaults to
        ``self["resource"]``; use ``issuer`` when a third party signs on behalf
        of the resource::

            from joserfc.jwk import RSAKey

            key = RSAKey.generate_key(2048)
            metadata.sign_metadata(key)
            metadata.sign_metadata(key, algorithm="RS512")
            metadata.sign_metadata(key, issuer="https://auth.example.com")
        """
        key = import_any_key(key)

        if algorithm is None:
            alg = JWSRegistry.guess_algorithm(key, JWSRegistry.Strategy.RECOMMENDED)
            if alg is None:
                raise ValueError(
                    "Cannot determine algorithm for this key type, "
                    "please provide algorithm explicitly"
                )
            algorithm = alg.name

        claims = {}
        for k, v in self.items():
            if k == "signed_metadata":
                continue
            claims[k] = v

        claims["iss"] = issuer or self["resource"]

        token = jwt.encode({"alg": algorithm}, claims, key, algorithms=[algorithm])
        self["signed_metadata"] = token
        return token

    @property
    def tls_client_certificate_bound_access_tokens(self):
        """Return the value of this field, or ``False`` if it is missing."""
        # rfc9728 §2: "If omitted, the default value is false."
        return self.get("tls_client_certificate_bound_access_tokens", False)

    @property
    def dpop_bound_access_tokens_required(self):
        """Return the value of this field, or ``False`` if it is missing."""
        # rfc9728 §2: "If omitted, the default value is false."
        return self.get("dpop_bound_access_tokens_required", False)

    def validate(self):
        """Validate all the protected resource metadata values."""
        for key in self.REGISTRY_KEYS:
            object.__getattribute__(self, f"validate_{key}")()

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTRY_KEYS:
                return self.get(key)
            raise error


class ResourceMetadataExtension:
    """ResourceProtector extension that injects ``resource_metadata`` into
    ``WWW-Authenticate`` error responses per :rfc:`9728#section-5`.

    Usage::

        from authlib.oauth2.rfc9728 import (
            ProtectedResourceMetadata,
            ResourceMetadataExtension,
        )

        metadata = ProtectedResourceMetadata({"resource": "https://api.example.com/"})
        require_oauth.register_extension(ResourceMetadataExtension(metadata))

    :param metadata: The :class:`ProtectedResourceMetadata` of the resource.
    """

    def __init__(self, metadata):
        self.metadata = metadata

    def get_resource_metadata_url(self, request):
        """Return the ``resource_metadata`` URL for this request.

        By default, it is the well-known URL of the ``resource`` metadata, for
        all the requests. Override it to send a different URL for each route.
        You then have to serve a metadata document at each of these URLs::

            class MyResourceMetadataExtension(ResourceMetadataExtension):
                def get_resource_metadata_url(self, request):
                    return get_well_known_url(request.uri, external=True)

        :param request: The OAuth2 request being validated.
        :returns: The URL of the protected resource metadata.
        """
        return get_well_known_url(self.metadata["resource"], external=True)

    def _patch_error(self, exc, instance, url):
        """Patch ``exc.get_headers`` to inject ``resource_metadata`` into WWW-Authenticate."""
        original_get_headers = exc.get_headers

        def patched_get_headers():
            headers = original_get_headers()
            www_found = False
            result = []
            for name, value in headers:
                if name.lower() == "www-authenticate":
                    www_found = True
                    scheme, _, rest = value.partition(" ")
                    value = (
                        f'{scheme} resource_metadata="{url}", {rest}'
                        if rest
                        else f'{scheme} resource_metadata="{url}"'
                    )
                result.append((name, value))

            if not www_found:
                auth_type = getattr(instance, "_default_auth_type", None) or "Bearer"
                result.append(
                    ("WWW-Authenticate", f'{auth_type} resource_metadata="{url}"')
                )

            return result

        exc.get_headers = patched_get_headers

    def __call__(self, protector):
        def inject_www_authenticate_header(
            instance, original, scopes, request, **kwargs
        ):
            try:
                return original(scopes, request, **kwargs)
            except Exception as exc:
                if getattr(exc, "status_code", 0) in (401, 403):
                    url = self.get_resource_metadata_url(request)
                    self._patch_error(exc, instance, url)
                raise

        protector.register_hook(
            "replace_validate_request", inject_www_authenticate_header
        )


def _validate_non_empty_array(metadata, key):
    validate_array_value(metadata, key)
    # rfc9728 §3.2: "Parameters with multiple values are represented as JSON
    # arrays. Parameters with zero values MUST be omitted from the response."
    values = metadata.get(key)
    if values == []:
        raise ValueError(f'"{key}" MUST be omitted when empty')

    if values is not None and not all(isinstance(v, str) for v in values):
        raise ValueError(f'"{key}" MUST contain strings')


def _localized_keys(metadata, key):
    return [k for k in metadata if k == key or k.startswith(f"{key}#")]


def _validate_localized_string(metadata, key):
    for k in _localized_keys(metadata, key):
        value = metadata[k]
        if value is not None and not isinstance(value, str):
            raise ValueError(f'"{k}" MUST be a string')


def _validate_localized_url(metadata, key):
    for k in _localized_keys(metadata, key):
        value = metadata[k]
        if value is None:
            continue

        if not isinstance(value, str) or not is_valid_url(value):
            raise ValueError(f'"{k}" MUST be a URL')
