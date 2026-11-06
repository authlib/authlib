"""authlib.oauth2.rfc9470.
~~~~~~~~~~~~~~~~~~~~~~~~

OAuth 2.0 Step Up Authentication Challenge Protocol.

https://www.rfc-editor.org/rfc/rfc9470
"""

from .authorization_server import StepUpAuthentication
from .authorization_server import get_max_age
from .authorization_server import is_login_required

__all__ = ["StepUpAuthentication", "get_max_age", "is_login_required"]
