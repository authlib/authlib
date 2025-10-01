"""authlib.oauth2.rfc9728.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
OAuth 2.0 Protected Resource Metadata.

https://tools.ietf.org/html/rfc9728
"""

from .models import ProtectedResourceMetadata
from .well_known import get_well_known_url

__all__ = ["ProtectedResourceMetadata", "get_well_known_url"]
