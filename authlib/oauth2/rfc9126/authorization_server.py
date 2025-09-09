from typing import Optional

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.authenticate_client import _validate_client
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc9101.authorization_server import RequestURIHandler
from authlib.oauth2.rfc9126.discovery import AuthorizationServerMetadata
from authlib.oauth2.rfc9126.endpoint import PushedAuthorizationEndpoint
from authlib.oauth2.rfc9126.registration import ClientMetadataClaims


class PushedAuthorizationRequest(RequestURIHandler):
    REQUEST_SOURCE = "pushed_authorization_request"

    def __call__(self, server: AuthorizationServer):
        super().__call__(server)
        self.REQUEST_URI_EXTENSION.register_handler(self)
        server.register_hook("after_get_authorization_grant", self.confirm_pushed_authorization_request)

    def get_request_uri_data(self, request: OAuth2Request) -> Optional[dict]:
        if not self._should_proceed_with_request_uri_parameter(request):
            return None
        return self.get_request_payload(request.payload.data["request_uri"])

    def handle_request_uri_data(self, request_uri_data: dict, server: AuthorizationServer,
                                request: OAuth2Request):
        _validate_client(server.query_client, request.payload.client_id)
        payload = BasicOAuth2Payload(request_uri_data)
        request.payload = payload
        request.source = self.REQUEST_SOURCE

    def confirm_pushed_authorization_request(self, server, grant):
        request = grant.request
        if request.source != self.REQUEST_SOURCE:
            client = _validate_client(server.query_client, request.payload.client_id)
            client_metadata = self.get_client_metadata(client)
            if client_metadata and client_metadata.require_pushed_authorization_requests:
                raise InvalidRequestError(
                    "Authorization requests for this client must use pushed authorization requests.",
                    state=request.payload.state,
                )

            server_metadata = self.get_server_metadata()
            if server_metadata and server_metadata.require_pushed_authorization_requests:
                raise InvalidRequestError(
                    "Authorization requests for this server must use pushed authorization requests.",
                    state=request.payload.state,
                )

    def _should_proceed_with_request_uri_parameter(self, request: OAuth2Request):
        if isinstance(request.endpoint, PushedAuthorizationEndpoint):
            return False

        if "request_uri" not in request.payload.data:
            return False

        return True

    def get_request_payload(self, request_uri: str) -> Optional[dict]:
        """Get the previously saved request payload by ``request_uri``

        request_uri SHOULD be one-time use, so devs MAY delete immediately
        after querying if desired. Expired request_uris MUST be handled as
        invalid and return None.

        Developers MUST implement it in subclass::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_request_payload(self, request_uri: str) -> Optional[dict]:
                    return PushedAuthorizationRequestObject.get(request_uri=request_uri).payload

        :param request_uri: the `request_uri` to look up
        :return: the dict of the parameters from the initial authorization request, or None
        """
        raise NotImplementedError()

    def get_client_metadata(self, client: ClientMixin) -> ClientMetadataClaims:
        """Return the client metadata.

        When the ``require_pushed_authorization_requests`` claim is :data:`True`,
        the client must start the authorization process via initiating a Pushed
        Authorization Request. If omitted, the default value is false.::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_client_metadata(self):
                    return ClientMetadataClaims({
                        "require_pushed_authorization_requests": ...,
                    })

        """
        return ClientMetadataClaims()

    def get_server_metadata(self) -> AuthorizationServerMetadata:
        """Return server metadata which includes supported grant types,
        response types and etc.

        When the ``require_pushed_authorization_requests`` claim is :data:`True`,
        all clients must start the authorization process via initiating a Pushed
        Authorization Request. If omitted, the default value is false.::

            class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
                def get_server_metadata(self):
                    return AuthorizationServerMetadata({
                        "issuer": ...,
                        "authorization_endpoint": ...,
                        "require_pushed_authorization_requests": ...,
                    })

        """
        return AuthorizationServerMetadata()
