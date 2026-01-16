class AuthorizationServerMetadata(dict):
    REGISTRY_KEYS = ["require_signed_request_object"]

    def validate_require_signed_request_object(self):
        """Indicates where authorization request needs to be protected as
        Request Object and provided through either request or request_uri
        parameter.
        """
        key = "require_signed_request_object"
        if key in self and self[key] not in (True, False):
            raise ValueError(f'"{key}" MUST be boolean')
