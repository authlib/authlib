from authlib.oauth2.rfc8414.models import validate_array_value


class AuthorizationServerMetadata(dict):
    """Authorization Server Metadata extension for RFC9728 (Section 4).

    This class can be used with
    :meth:`~authlib.oauth2.rfc8414.AuthorizationServerMetadata.validate`
    to validate RFC9728-specific metadata::

        from authlib.oauth2 import rfc8414, rfc9728

        metadata = rfc8414.AuthorizationServerMetadata(data)
        metadata.validate(metadata_classes=[rfc9728.AuthorizationServerMetadata])
    """

    REGISTRY_KEYS = ["protected_resources"]

    def validate_protected_resources(self):
        """OPTIONAL. JSON array of resource identifiers for protected
        resources that accept access tokens issued by this authorization
        server (Section 4).
        """
        validate_array_value(self, "protected_resources")
