from authlib.common.security import is_secure_transport
from authlib.oauth2.rfc8414.models import _validate_boolean_value


class AuthorizationServerMetadata(dict):
    REGISTRY_KEYS = [
        "pushed_authorization_request_endpoint",
        "require_pushed_authorization_requests"
    ]

    def validate_pushed_authorization_request_endpoint(self):
        """The URL of the pushed authorization request endpoint at which a
        client can post an authorization request to exchange for a
        request_uri value usable at the authorization server.
        """
        url = self.get("pushed_authorization_request_endpoint")
        if url and not is_secure_transport(url):
            raise ValueError('"pushed_authorization_request_endpoint" MUST use "https" scheme')

        require_pushed_authorization_requests = self.require_pushed_authorization_requests
        if require_pushed_authorization_requests and not url:
            raise ValueError('"pushed_authorization_request_endpoint" is required')

    def validate_require_pushed_authorization_requests(self):
        """Boolean parameter indicating whether the authorization server
        accepts authorization request data only via PAR. If omitted, the
        default value is false.
        """
        _validate_boolean_value(self, "require_pushed_authorization_requests")

    @property
    def require_pushed_authorization_requests(self):
        # If omitted, the default value is false.
        return self.get("require_pushed_authorization_requests", False)
