"""authlib.oauth2.rfc6750.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
The OAuth 2.0 Authorization Framework: Bearer Token Usage.

https://tools.ietf.org/html/rfc6750
"""

from .errors import InsufficientScopeError
from .errors import InvalidTokenError
from .parameters import add_bearer_token
from .token import BearerTokenGenerator
from .validator import BearerTokenValidator

# Backwards-compatibility alias:
# Historically, Authlib exported `BearerToken` as a generator type.
# Keep this alias for existing integrations, but prefer
# `BearerTokenGenerator` for new code. When the deprecation policy is
# implemented, `BearerToken` should emit a DeprecationWarning.
BearerToken = BearerTokenGenerator


__all__ = [
    "InvalidTokenError",
    "InsufficientScopeError",
    "add_bearer_token",
    "BearerToken",
    "BearerTokenGenerator",
    "BearerTokenValidator",
]
