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

    When :meth:`get_client_request_object_signing_alg` returns the algorithm
    registered by the client, request objects signed with another algorithm are
    rejected, as required by OpenID Connect Core §6.3.2.
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

    def get_client_request_object_signing_alg(self, client: ClientMixin) -> str | None:
        """Return the ``request_object_signing_alg`` registered by this client.

        Per OpenID Connect Registration §2, request objects from the client
        MUST be rejected if they are not signed with this algorithm, including
        unsigned request objects when it is not ``none``. The algorithm must
        also be accepted by :meth:`get_request_object_signing_algorithms`::

            def get_client_request_object_signing_alg(self, client):
                return client.request_object_signing_alg

        If it returns :data:`None`, as by default, any algorithm accepted by
        the server is accepted for this client.
        """
        return None

    def _restrict_signing_algorithms(
        self, client: ClientMixin, algorithms: list[str]
    ) -> list[str]:
        registered = self.get_client_request_object_signing_alg(client)
        if not registered:
            return algorithms
        return [algorithm for algorithm in algorithms if algorithm == registered]
