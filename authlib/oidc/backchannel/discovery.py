"""Provider metadata for OIDC Back-Channel Logout 1.0.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""


class OpenIDProviderMetadata(dict):
    """Provider metadata for OIDC Back-Channel Logout 1.0.

    This can be used with :ref:`specs/rfc8414` discovery metadata::

        from authlib.oidc import backchannel
        from authlib.oidc import discovery

        metadata = discovery.OpenIDProviderMetadata({
            ...,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
        })
        metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])
    """

    REGISTRY_KEYS = [
        "backchannel_logout_supported",
        "backchannel_logout_session_supported",
    ]

    def validate_backchannel_logout_supported(self):
        # backchannel §2.1: "backchannel_logout_supported - OPTIONAL. Boolean value
        # specifying whether the OP supports back-channel logout, with true indicating
        # support. If omitted, the default value is false."
        value = self.get("backchannel_logout_supported")
        if value is not None and not isinstance(value, bool):
            raise ValueError('"backchannel_logout_supported" MUST be a boolean')

    def validate_backchannel_logout_session_supported(self):
        # backchannel §2.1: "backchannel_logout_session_supported - OPTIONAL. Boolean
        # value specifying whether the OP can pass a sid (session ID) Claim in the
        # Logout Token to identify the RP session with the OP. If supported, the
        # sid Claim is also included in ID Tokens issued by the OP. If omitted, the
        # default value is false."
        value = self.get("backchannel_logout_session_supported")
        if value is not None and not isinstance(value, bool):
            raise ValueError('"backchannel_logout_session_supported" MUST be a boolean')
