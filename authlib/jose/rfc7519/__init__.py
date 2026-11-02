"""authlib.jose.rfc7519.
~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
JSON Web Token (JWT).

:rfc:`7519`
"""

from .claims import BaseClaims
from .claims import JWTClaims
from .jwt import JsonWebToken

__all__ = ["JsonWebToken", "BaseClaims", "JWTClaims"]
