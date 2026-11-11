"""authlib.oauth2.rfc9470.
~~~~~~~~~~~~~~~~~~~~~~~~

OAuth 2.0 Step Up Authentication Challenge Protocol.

https://www.rfc-editor.org/rfc/rfc9470
"""

from .authorization_server import StepUpAuthentication
from .authorization_server import get_max_age
from .authorization_server import get_requested_acr_values
from .authorization_server import is_login_required
from .authorization_server import set_authentication_context
from .models import AuthorizationSessionMixin

__all__ = [
    "AuthorizationSessionMixin",
    "StepUpAuthentication",
    "get_max_age",
    "get_requested_acr_values",
    "is_login_required",
    "set_authentication_context",
]
