"""Provider metadata for Initiating User Registration via OpenID Connect 1.0.

https://openid.net/specs/openid-connect-prompt-create-1_0.html
"""

from authlib.oauth2.rfc8414.models import validate_array_value


class OpenIDProviderMetadata(dict):
    """Provider metadata for Initiating User Registration via OpenID Connect 1.0.

    This can be used with :ref:`specs/rfc8414` discovery metadata::

        from authlib.oidc import discovery
        from authlib.oidc import prompt_create

        metadata = discovery.OpenIDProviderMetadata({
            ...,
            "prompt_values_supported": [
                "none",
                "login",
                "consent",
                "select_account",
                "create",
            ],
        })
        metadata.validate(metadata_classes=[prompt_create.OpenIDProviderMetadata])
    """

    REGISTRY_KEYS = ["prompt_values_supported"]

    def validate_prompt_values_supported(self):
        """Check that ``prompt_values_supported`` is a list that contains ``create``."""
        # prompt-create §4.2: "If an OpenID Provider supports this specification
        # it MUST define this metadata element in the openid-configuration file."
        values = self.get("prompt_values_supported")
        if values is None:
            raise ValueError('"prompt_values_supported" is required')

        validate_array_value(self, "prompt_values_supported")
        if not all(isinstance(value, str) for value in values):
            raise ValueError('"prompt_values_supported" MUST contain strings')

        # prompt-create §4.2: "a value of create in the array indicates to the
        # Relying party that this OpenID Provider supports this specification."
        if "create" not in values:
            raise ValueError('"prompt_values_supported" MUST contain "create"')
