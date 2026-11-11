"""authlib.oidc.unmet_authentication_requirements.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenID Connect Core Error Code unmet_authentication_requirements.

https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html
"""

from .authorization_server import UnmetAuthenticationRequirements
from .errors import UnmetAuthenticationRequirementsError

__all__ = [
    "UnmetAuthenticationRequirements",
    "UnmetAuthenticationRequirementsError",
]
