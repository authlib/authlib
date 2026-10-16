"""authlib.oidc.backchannel.
~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenID Connect Back-Channel Logout 1.0 Implementation.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

from .discovery import OpenIDProviderMetadata
from .logout_token import BACKCHANNEL_LOGOUT_EVENT
from .logout_token import create_logout_token
from .registration import ClientMetadataClaims
from .sender import BackchannelLogoutExtension

__all__ = [
    "BackchannelLogoutExtension",
    "ClientMetadataClaims",
    "OpenIDProviderMetadata",
    "create_logout_token",
    "BACKCHANNEL_LOGOUT_EVENT",
]
