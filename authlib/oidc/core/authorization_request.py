from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oauth2.rfc9101 import JWTAuthenticationRequest
from authlib.oauth2.rfc9101.errors import InvalidRequestUriError


class OpenIDJWTAuthenticationRequest(JWTAuthenticationRequest):
    """JAR extension with OpenID Connect request URI registration checks.

    When provider metadata ``require_request_uri_registration`` is true,
    references must match :meth:`get_client_request_uris` before the application's
    :meth:`validate_request_uri` policy is called. Registration alone does not
    permit retrieval; a secure validation policy must also accept the URI.
    """

    def _get_raw_request_object(
        self, request: OAuth2Request, client: ClientMixin
    ) -> str:
        if "request_uri" in request.payload.data:
            metadata = self.get_server_metadata()
            if metadata.get("require_request_uri_registration", False):
                request_uri = request.payload.data["request_uri"]
                if request_uri not in self.get_client_request_uris(client):
                    raise InvalidRequestUriError(state=request.payload.state)
        return super()._get_raw_request_object(request, client)

    def get_client_request_uris(self, client: ClientMixin) -> list[str]:
        """Return URIs registered for this client using OIDC ``request_uris``.

        Implement this hook when URI registration is required. The default is
        an empty list, so no URI satisfies a registration requirement::

            def get_client_request_uris(self, client):
                return client.request_uris

        Validate destinations during registration and retrieval; client-supplied
        metadata alone does not establish that a destination is safe.
        """
        return []
