from authlib.oauth2.rfc8414.models import _validate_alg_values


class AuthorizationServerMetadata(dict):
    REGISTRY_KEYS = ["dpop_signing_alg_values_supported"]

    def validate_dpop_signing_alg_values_supported(self):
        """OPTIONAL.  A JSON array containing a list of the JWS alg values
        (from the [IANA.JOSE.ALGS] registry) supported by the authorization
        server for DPoP proof JWTs.
        """
        _validate_alg_values(
            self,
            "dpop_signing_alg_values_supported",
            self.dpop_signing_alg_values_supported,
        )

    @property
    def dpop_signing_alg_values_supported(self):
        #: If omitted, the set of JWS alg values MUST be
        #: determined by other means
        #: here, we use "ES256"
        return self.get("dpop_signing_alg_values_supported", ["ES256"])
