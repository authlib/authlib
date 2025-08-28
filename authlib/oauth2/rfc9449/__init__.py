"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
The OAuth 2.0 Demonstrating Proof of Possession (DPoP).

https://tools.ietf.org/html/rfc9449
"""

from .parameters import add_dpop_token

__all__ = [
    "add_dpop_token",
]
