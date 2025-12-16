from .errors import InvalidClientMetadataError


def run_legacy_claims_validation(data, server_metadata, claims_classes):
    from authlib.jose.errors import JoseError

    client_metadata = {}
    for claims_class in claims_classes:
        options = (
            claims_class.get_claims_options(server_metadata)
            if hasattr(claims_class, "get_claims_options") and server_metadata
            else {}
        )
        claims = claims_class(data, {}, options, server_metadata)
        try:
            claims.validate()
        except JoseError as error:
            raise InvalidClientMetadataError(error.description) from error

        client_metadata.update(**claims.get_registered_claims())
    return client_metadata
