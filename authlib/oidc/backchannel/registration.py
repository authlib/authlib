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

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    oidc.registration.ClientMetadataClaims,
                    oidc.backchannel.ClientMetadataClaims,
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
        # backchannel §2.2: "backchannel_logout_uri - OPTIONAL. RP URL that will
        # cause the RP to log itself out when sent a Logout Token by the OP. This
        # URL MUST use the https scheme and MAY contain port, path, and query
        # parameter components; it MUST NOT contain a fragment component."
        uri = self.get("backchannel_logout_uri")
        if not uri:
            return

        if not is_valid_url(uri, fragments_allowed=False):
            raise InvalidClaimError("backchannel_logout_uri")

        if not is_secure_transport(uri):
            raise ValueError('"backchannel_logout_uri" MUST use "https" scheme')

    def _validate_backchannel_logout_session_required(self):
        # backchannel §2.2: "backchannel_logout_session_required - OPTIONAL.
        # Boolean value specifying whether the RP requires that a sid (session ID)
        # Claim be included in the Logout Token to identify the RP session with
        # the OP when the backchannel_logout_uri is used. If omitted, the default
        # value is false."
        value = self.get("backchannel_logout_session_required")
        if value is not None and not isinstance(value, bool):
            raise InvalidClaimError("backchannel_logout_session_required")
