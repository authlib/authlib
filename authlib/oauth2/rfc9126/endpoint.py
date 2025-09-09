import logging
import time
from typing import Tuple

from authlib.common.security import generate_token
from authlib.consts import default_json_headers
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from authlib.oauth2.rfc6749.errors import UnauthorizedClientError
from authlib.oauth2.rfc6749.grants import BaseGrant

log = logging.getLogger(__name__)


class PushedAuthorizationEndpoint:
    ENDPOINT_NAME = "pushed_authorization"

    #: Generated "request_uri" length
    REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri"
    REQUEST_URI_LENGTH = 48
    REQUEST_URI_EXPIRES_IN = 60  # 1 minute

    def __init__(self, server: AuthorizationServer):
        self.server = server

    def __call__(self, request):
        return self.create_endpoint_response(request)

    def create_endpoint_request(self, request):
        return self.server.create_oauth2_request(request)

    def create_endpoint_response(self, request):
        # Must be done before `server.get_authorization_grant()` to ensure `request_uri` isn't used as part of JAR
        if request.payload.request_uri:
            raise InvalidRequestError(
                "The 'request_uri' parameter MUST NOT be present in the pushed authorization request.")

        grant = self.server.get_authorization_grant(request)
        self.validate_pushed_authorization_request(grant)
        grant.validate_authorization_request()

        request_uri, expires_in = self.generate_request_uri()
        self.save_request_payload(request.payload.data, request_uri, int(time.time() + expires_in))

        response = {
            "request_uri": request_uri,
            "expires_in": expires_in
        }

        return 201, response, default_json_headers

    def validate_pushed_authorization_request(self, grant: BaseGrant):
        client = grant.authenticate_token_endpoint_client()
        log.debug("Validate PAR request of %r", client)
        if not client.check_grant_type(grant.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={grant.GRANT_TYPE}'"
            )

    def generate_request_uri(self) -> Tuple[str, int]:
        """The method to generate "request_uri" value for authorization code data
        for Pushed Authorization Requests.

        Developers MAY rewrite this method, or customize the code length and expires with::

            class PushedAuthorizationEndpoint(rfc9126.PushedAuthorizationEndpoint):
                REQUEST_URI_PREFIX = "urn:example"  # default is "urn:ietf:params:oauth:request_uri"
                REQUEST_URI_LENGTH = 32  # default is 48
                REQUEST_URI_EXPIRES_IN = 120  # default is 60

        :return: a tuple containing the `request_uri` and `expires_in`
        """
        return f"{self.REQUEST_URI_PREFIX}:{generate_token(self.REQUEST_URI_LENGTH)}", self.REQUEST_URI_EXPIRES_IN

    def save_request_payload(self, payload: dict, request_uri: str, expires_at: int):
        """Save the request ``payload`` at ``request_uri``, with ``expires_at``.

        Developers MUST implement it in subclass::

            class PushedAuthorizationEndpoint(rfc9126.PushedAuthorizationEndpoint):
                def save_request_payload(self, payload: dict, request_uri: str, expires_in: int):
                    item = PushedAuthorizationRequestObject(
                        request_uri=request_uri,
                        payload=payload,
                        expires_at=expires_at,
                    )
                    item.save()

        :param payload: a dict of the parameters from the initial authorization request
        :param request_uri: the generated `request_uri` to map the payload against
        :param expires_at: when the `request_uri` expires
        """
        raise NotImplementedError()
