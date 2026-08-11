"""authlib.oauth2.drafts.
~~~~~~~~~~~~~~~~~~~~~~~~

Implementations of OAuth 2.0 specifications that are still in IETF draft
status.  APIs in this package may change to track spec revisions until
the corresponding RFC is published.
"""

from .id_jag import IDJAGGrant

__all__ = ["IDJAGGrant"]

