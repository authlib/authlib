"""authlib.oauth2.rfc8693.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Token Exchange.

:rfc:`8693`
"""

from .errors import InvalidTargetError
from .token_exchange import ACCESS_TOKEN_TYPE
from .token_exchange import ID_TOKEN_TYPE
from .token_exchange import JWT_TOKEN_TYPE
from .token_exchange import REFRESH_TOKEN_TYPE
from .token_exchange import SAML1_TOKEN_TYPE
from .token_exchange import SAML2_TOKEN_TYPE
from .token_exchange import TOKEN_EXCHANGE_GRANT_TYPE
from .token_exchange import TokenExchangeGrant

__all__ = [
    "TokenExchangeGrant",
    "TOKEN_EXCHANGE_GRANT_TYPE",
    "InvalidTargetError",
    "ACCESS_TOKEN_TYPE",
    "REFRESH_TOKEN_TYPE",
    "ID_TOKEN_TYPE",
    "SAML1_TOKEN_TYPE",
    "SAML2_TOKEN_TYPE",
    "JWT_TOKEN_TYPE",
]
