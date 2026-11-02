"""Client metadata for OIDC Back-Channel Logout 1.0.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

from joserfc.errors import InvalidClaimError

from authlib.common.security import is_secure_transport
from authlib.common.urls import is_valid_url
from authlib.oauth2.claims import BaseClaims


class ClientMetadataClaims(BaseClaims):
    """Client metadata for OIDC Back-Channel Logout 1.0.

    This can be used with :ref:`specs/rfc7591` and :ref:`specs/rfc7592` endpoints::

        from authlib.oauth2 import rfc7591
        from authlib.oidc import backchannel
        from authlib.oidc import registration

        server.register_endpoint(
            MyClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    registration.ClientMetadataClaims,
                    backchannel.ClientMetadataClaims,
                ]
            )
        )
    """

    REGISTERED_CLAIMS = [
        "backchannel_logout_uri",
        "backchannel_logout_session_required",
    ]

    def validate(self, now=None, leeway=0):
        super().validate(now, leeway)
        self._validate_backchannel_logout_uri()
        self._validate_backchannel_logout_session_required()

    def _validate_backchannel_logout_uri(self):
        # backchannel §2.2: "The back-channel logout URI MUST be an absolute URI
        # [...]. The back-channel logout URI MUST NOT include a fragment
        # component."
        # backchannel §2.2: "backchannel_logout_uri - OPTIONAL. RP URL that will
        # cause the RP to log itself out when sent a Logout Token by the OP. This
        # URL SHOULD use the https scheme and MAY contain port, path, and query
        # parameter components; however, it MAY use the http scheme, provided
        # that the Client Type is confidential, as defined in Section 2.1 of
        # OAuth 2.0, and provided the OP allows the use of http RP URIs."
        uri = self.get("backchannel_logout_uri")
        if not uri:
            return

        if not is_valid_url(uri, fragments_allowed=False):
            raise InvalidClaimError("backchannel_logout_uri")

        is_public = self.get("token_endpoint_auth_method") == "none"
        if is_public and not is_secure_transport(uri, allow_loopback=False):
            raise InvalidClaimError("backchannel_logout_uri")

    def _validate_backchannel_logout_session_required(self):
        # backchannel §2.2: "backchannel_logout_session_required - OPTIONAL.
        # Boolean value specifying whether the RP requires that a sid (session ID)
        # Claim be included in the Logout Token to identify the RP session with
        # the OP when the backchannel_logout_uri is used. If omitted, the default
        # value is false."
        value = self.get("backchannel_logout_session_required")
        if value is not None and not isinstance(value, bool):
            raise InvalidClaimError("backchannel_logout_session_required")
