"""authlib.oidc.prompt_create.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Initiating User Registration via OpenID Connect 1.0 Implementation.

https://openid.net/specs/openid-connect-prompt-create-1_0.html
"""

from .discovery import OpenIDProviderMetadata
from .prompt import PromptValues

__all__ = [
    "OpenIDProviderMetadata",
    "PromptValues",
]
