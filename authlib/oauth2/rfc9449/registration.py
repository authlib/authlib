from authlib.oauth2.rfc8414.models import _validate_boolean_value


class ClientMetadataClaims(dict):
    """Additional client metadata can be used with :ref:`specs/rfc7591` and :ref:`specs/rfc7592` endpoints.

    This can be used with::

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    rfc9449.ClientMetadataClaims,
                ]
            )
        )

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    rfc9449.ClientMetadataClaims,
                ]
            )
        )

    """

    REGISTERED_CLAIMS = [
        "dpop_bound_access_tokens",
    ]

    def validate(self):
        self.validate_dpop_bound_access_tokens()

    def validate_dpop_bound_access_tokens(self):
        """A boolean value specifying whether the client always
        uses DPoP for token requests.
        If omitted, the default value is false.
        """
        _validate_boolean_value(self, "dpop_bound_access_tokens")

    @property
    def dpop_bound_access_tokens(self):
        # If omitted, the default value is false.
        return self.get("dpop_bound_access_tokens", False)
