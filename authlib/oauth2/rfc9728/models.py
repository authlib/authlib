"""Support for OAuth 2.0 Protected Resource Metadata model validation"""
from authlib.common.security import is_secure_transport
from authlib.common.urls import is_valid_url
from authlib.common.urls import urlparse


class ProtectedResourceMetadata(dict):
    """Define Protected Resource Metadata via `Section 2`_ in RFC9728_.

    .. _RFC9728: https://tools.ietf.org/html/rfc9728
    .. _`Section 2`: https://tools.ietf.org/html/rfc9728#section-2
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
        "dpop_bound_access_tokens_required"
    ]

    def validate_resource(self):
        """REQUIRED. The protected resource's resource identifier as defined in
        Section 1.2 of RFC9728.
        """
        resource = self.get("resource")

        #: 1. REQUIRED
        if not resource:
            raise ValueError('"resource" is required')

        parsed = urlparse.urlparse(resource)

        #: 2. uses the "https" scheme
        if not is_secure_transport(resource):
            raise ValueError('"resource" MUST use "https" scheme')

        #: 3. has no fragment
        if parsed.fragment:
            raise ValueError('"resource" has no fragment')

    def validate_authorization_servers(self):
        """OPTIONAL. JSON array containing a list of OAuth authorization server
        issuer identifiers, as defined in [RFC8414].
        """
        validate_array_value(self, "authorization_servers")

    def validate_jwks_uri(self):
        """OPTIONAL.  URL of the protected resource's JSON Web Key (JWK) Set 
        [JWK] document. This contains public keys belonging to the protected 
        resource, such as signing key(s) that the resource server uses to sign 
        resource responses. This URL MUST use the https scheme. When both 
        signing and encryption keys are made available, a use (public key use) 
        parameter value is REQUIRED for all keys in the referenced JWK Set to 
        indicate each key's intended usage.

        """
        url = self.get("jwks_uri")
        if url and not is_secure_transport(url):
            raise ValueError('"jwks_uri" MUST use "https" scheme')

    def validate_scopes_supported(self):
        """RECOMMENDED. JSON array containing a list of scope values, as 
        defined in OAuth 2.0 [RFC6749], that are used in authorization 
        requests to request access to this protected resource. Protected
        resources MAY choose not to advertise some scope values supported
        even when this parameter is used.
        """
        validate_array_value(self, "scopes_supported")

    def validate_bearer_methods_supported(self):
        """OPTIONAL. JSON array containing a list of the supported methods of
        sending an OAuth 2.0 bearer token [RFC6750] to the protected resource.
        Defined values are ["header", "body", "query"], corresponding to
        Sections 2.1, 2.2, and 2.3 of [RFC6750]. The empty array [] can be used
        to indicate that no bearer methods are supported. If this entry is 
        omitted, no default bearer methods supported are implied, nor does its
        absence indicate that they are not supported.
        """
        validate_array_value(self, "bearer_methods_supported")

    def validate_resource_signing_alg_values_supported(self):
        """OPTIONAL. JSON array containing a list of the JWS [JWS] signing
        algorithms (alg values) [JWA] supported by the protected resource for
        signing resource responses, for instance, as described in 
        [FAPI.MessageSigning]. No default algorithms are implied if this entry
        is omitted. The value none MUST NOT be used.
        """
        value = self.get("resource_signing_alg_values_supported")
        if value and not isinstance(value, list):
            raise ValueError('"resource_signing_alg_values_supported" MUST be JSON array')

        if value and "none" in value:
            raise ValueError('the value "none" MUST NOT be used in '
                             '"validate_resource_signing_alg_values_supported"')

    def validate_resource_name(self):
        """Human-readable name of the protected resource intended for display
        to the end user. It is RECOMMENDED that protected resource metadata
        include this field. The value of this field MAY be internationalized,
        as described in Section 2.1.
        """
        # in the case of internationalized URL, the language tag
        # is added to the metadata parameter name
        # e.g resource_name#en
        value = self.get("resource_name")
        if value and not isinstance(value, str):
            raise ValueError('"resource_name" MUST be a string')

    def validate_resource_documentation(self):
        """OPTIONAL. URL of a page containing human-readable information that
        developers might want or need to know when using the protected
        resource. The value of this field MAY be internationalized, as
        described in Section 2.1.
        """
        # in the case of internationalized URL, the language tag
        # is added to the metadata parameter name
        # e.g resource_documentation#en

        value = self.get("resource_documentation")
        if value and not is_valid_url(value):
            raise ValueError('"resource_documentation" MUST be a URL')

    def validate_resource_policy_uri(self):
        """OPTIONAL. URL of a page containing human-readable information about
        the protected resource's requirements on how the client can use the
        data provided by the protected resource. The value of this field MAY be
        internationalized, as described in Section 2.1.

        """
        value = self.get("resource_policy_uri")
        if value and not is_valid_url(value):
            raise ValueError('"resource_policy_uri" MUST be a URL')

    def validate_resource_tos_uri(self):
        """OPTIONAL. URL of a page containing human-readable information about
        the protected resource's terms of service. The value of this field MAY
        be unternationalized, as described in Section 2.1.
        """
        value = self.get("resource_tos_uri")
        if value and not is_valid_url(value):
            raise ValueError('"resource_tos_uri" MUST be a URL')

    def validate_tls_client_certificate_bound_access_tokens(self):
        """OPTIONAL. Boolean value indicating protected resource support for
        mutual-TLS client certificate-bound access tokens [RFC8705]. If
        omitted, the default value is false.
        """
        value = self.get("tls_client_certificate_bound_access_tokens")
        if value and not isinstance(value, bool):
            raise ValueError('"tls_client_certificate_bound_access_tokens" MUST be a boolean')

    def validate_authorization_details_types_supported(self):
        """JSON array containing a list of the authorization details type
        values supported by the resource server when the authorization_details
        request parameter [RFC9396] is used.
        """
        validate_array_value(self, "authorization_details_types_supported")

    def validate_dpop_signing_alg_values_supported(self):
        """JSON array containing a list of the JWS alg values (from the
        "JSON Web Signature and Encryption Algorithms" registry [IANA.JOSE])
        supported by the resource server for validating 
        Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449].

        """
        validate_array_value(self, "dpop_signing_alg_values_supported")

    def validate_dpop_bound_access_tokens_required(self):
        """OPTIONAL. Boolean value specifying whether the protected resource
        always requires the use of DPoP-bound access tokens [RFC9449]. 
        If omitted, the default value is false.

        """
        value = self.get("dpop_bound_access_tokens_required")
        if value and not isinstance(value, bool):
            raise ValueError('"dpop_bound_access_tokens_required" MUST be a boolean')

    @property
    def tls_client_certificate_bound_access_tokens(self):
        """Set default value for "tls_client_certificate_bound_access_tokens" to False."""
        #: If omitted, the default value is false.
        return self.get("tls_client_certificate_bound_access_tokens", False)

    @property
    def dpop_bound_access_tokens_required(self):
        """Set default value for "dpop_bound_access_tokens_required" to False."""
        #: If omitted, the default value is false.
        return self.get("dpop_bound_access_tokens_required", False)

    def validate(self):
        """Validate all server metadata value."""
        for key in self.REGISTRY_KEYS:
            if '#' in key:
                # Handle internationalized keys
                split_key = key.split('#')
                if len(split_key) != 2:
                    raise ValueError(f'Invalid key format: {key}, expected "key#lang" format')
                # Now we have the key and the language tag, lets validate
                # the key without the language tag
                key = split_key[0]

            object.__getattribute__(self, f"validate_{key}")()

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTRY_KEYS:
                return self.get(key)
            raise error

def validate_array_value(metadata, key):
    """Helper function to validate that a metadata key is a JSON array."""
    values = metadata.get(key)
    if values is not None and not isinstance(values, list):
        raise ValueError(f'"{key}" MUST be JSON array')
