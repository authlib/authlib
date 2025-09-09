from authlib.oauth2.rfc8414.models import _validate_boolean_value


class ClientMetadataClaims(dict):
    """Additional client metadata can be used with :ref:`specs/rfc7591` and :ref:`specs/rfc7592` endpoints.

    This can be used with::

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    rfc9126.ClientMetadataClaims,
                ]
            )
        )

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    rfc9126.ClientMetadataClaims,
                ]
            )
        )

    """

    REGISTERED_CLAIMS = [
        "require_pushed_authorization_requests",
    ]

    def validate(self):
        self.validate_require_pushed_authorization_requests()

    def validate_require_pushed_authorization_requests(self):
        """Boolean parameter indicating whether the only means of initiating
        an authorization request the client is allowed to use is PAR. If
        omitted, the default value is false..
        """
        _validate_boolean_value(self, "require_pushed_authorization_requests")

    @property
    def require_pushed_authorization_requests(self):
        # If omitted, the default value is false.
        return self.get("require_pushed_authorization_requests", False)
