from abc import ABC
from typing import Any
from typing import Optional

from authlib.deprecate import deprecate
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from .discovery import AuthorizationServerMetadata
from .errors import InvalidRequestObjectError
from .errors import InvalidRequestUriError
from .errors import RequestNotSupportedError
from .errors import RequestUriNotSupportedError
from .registration import ClientMetadataClaims
from ..rfc6749 import AuthorizationServer
from ..rfc6749 import ClientMixin
from ..rfc6749 import InvalidRequestError
from ..rfc6749.authenticate_client import _validate_client
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request


class RequestURIExtension:
    def __init__(self):
        self._handlers: list['RequestURIHandler'] = []

    def __call__(self, server: AuthorizationServer):
        server.register_hook(
            "before_get_authorization_grant", self.handle_request_uri
        )

    def register_handler(self, handler: 'RequestURIHandler'):
        self._handlers.append(handler)

    def handle_request_uri(self, server: AuthorizationServer, request: OAuth2Request):
        if "request_uri" not in request.payload.data or len(self._handlers) == 0:
            return

        for handler in self._handlers:
            request_uri_data = handler.get_request_uri_data(request)
            if request_uri_data:
                handler.handle_request_uri_data(request_uri_data, server, request)
                return
        raise InvalidRequestUriError(state=request.payload.state)


class RequestURIHandler(ABC):
    REQUEST_URI_EXTENSION = RequestURIExtension()

    def __call__(self, server: AuthorizationServer):
        server.register_extension(self.REQUEST_URI_EXTENSION)

    def get_request_uri_data(self, request: OAuth2Request) -> Any:
        ...

    def handle_request_uri_data(self, request_uri_data: Any, server: AuthorizationServer, request: OAuth2Request):
        ...


class JWTAuthorizationRequest(RequestURIHandler):
    """Authorization server extension implementing the support
    for JWT secured authentication request, as defined in :rfc:`RFC9101 <9101>`.

    :param support_request: Whether to enable support for the ``request`` parameter.
    :param support_request_uri: Whether to enable support for the ``request_uri`` parameter.

    This extension is intended to be inherited and registered into the authorization server::

        class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
            def resolve_client_public_key(self, client: ClientMixin):
                return get_jwks_for_client(client)

            def get_request_object(self, request_uri: str):
                try:
                    return requests.get(request_uri).text
                except requests.Exception:
                    return None

            def get_server_metadata(self):
                return AuthorizationServerMetadata({
                    "issuer": ...,
                    "authorization_endpoint": ...,
                    "require_signed_request_object": ...,
                })

            def get_client_metadata(self):
                return ClientMetadataClaims({
                    "require_signed_request_object": ...,
                })

        authorization_server.register_extension(JWTAuthorizationRequest())
    """

    def __init__(self, support_request: bool = True, support_request_uri: bool = True):
        self.support_request = support_request
        self.support_request_uri = support_request_uri

    def __call__(self, authorization_server: AuthorizationServer):
        super().__call__(authorization_server)
        if self.support_request_uri:
            self.REQUEST_URI_EXTENSION.register_handler(self)
        if self.support_request:
            authorization_server.register_hook(
                "before_get_authorization_grant", self.handle_request_data
            )

    def get_request_uri_data(self, request: OAuth2Request) -> Optional[str]:
        if not self._should_proceed_with_request_uri_parameter(request):
            return None
        return self._get_raw_request_object(request)

    def handle_request_uri_data(self, request_uri_data: str, server: AuthorizationServer, request: OAuth2Request):
        self._handle_raw_request_object(request_uri_data, server, request)

    def handle_request_data(self, server: AuthorizationServer, request: OAuth2Request):
        if not self._should_proceed_with_request_parameter(request):
            return
        raw_request_object = self._get_raw_request_object(request)
        self._handle_raw_request_object(raw_request_object, server, request)

    def _handle_raw_request_object(self, raw_request_object: str, server: AuthorizationServer, request: OAuth2Request):
        client = _validate_client(server.query_client, request.payload.client_id)
        self._validate_authorization_request(request, client)

        request_object = self._decode_request_object(request, client, raw_request_object)
        payload = BasicOAuth2Payload(request_object)
        request.payload = payload
        request.source = "jwt_authorization_request"

    def _should_proceed_with_request_uri_parameter(self, request: OAuth2Request):
        if "request" in request.payload.data and "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=request.payload.state,
            )

        if "request_uri" in request.payload.data and self.support_request_uri:
            return True

        return False

    def _should_proceed_with_request_parameter(self, request: OAuth2Request):
        if "request" in request.payload.data and "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=request.payload.state,
            )

        if "request" in request.payload.data and self.support_request:
            return True

        return False

    def _validate_authorization_request(self, request: OAuth2Request, client: ClientMixin):
        if "request" in request.payload.data and "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=request.payload.state,
            )

        if "request" in request.payload.data:
            if not self.support_request:
                raise RequestNotSupportedError(state=request.payload.state)

        if "request_uri" in request.payload.data:
            if not self.support_request_uri:
                raise RequestUriNotSupportedError(state=request.payload.state)

        # When the value of it [require_signed_request_object] as client metadata is true,
        # then the server MUST reject the authorization request
        # from the client that does not conform to this specification.
        client_metadata = self.get_client_metadata(client)
        if client_metadata.require_signed_request_object:
            raise InvalidRequestError(
                "Authorization requests for this client must use signed request objects.",
                state=request.payload.state,
            )

        # When the value of it [require_signed_request_object] as server metadata is true,
        # then the server MUST reject the authorization request
        # from any client that does not conform to this specification.
        server_metadata = self.get_server_metadata()
        if server_metadata and server_metadata.require_signed_request_object:
            raise InvalidRequestError(
                "Authorization requests for this server must use signed request objects.",
                state=request.payload.state,
            )

    def _get_raw_request_object(self, request: OAuth2Request) -> str:
        if "request_uri" in request.payload.data:
            raw_request_object = self.get_request_object(request.payload.data["request_uri"])
        else:
            raw_request_object = request.payload.data["request"]

        return raw_request_object

    def _decode_request_object(self, request, client: ClientMixin, raw_request_object: str):
        jwks = self.resolve_client_public_key(client)

        try:
            request_object = jwt.decode(raw_request_object, jwks)
            request_object.validate()

        except JoseError as error:
            raise InvalidRequestObjectError(
                description=error.description or InvalidRequestObjectError.description,
                state=request.payload.state,
            ) from error

        # It MUST also reject the request if the Request Object uses an
        # alg value of none when this server metadata value is true.
        # If omitted, the default value is false.
        client_metadata = self.get_client_metadata(client)
        if (
            client_metadata
            and client_metadata.require_signed_request_object
            and request_object.header["alg"] == "none"
        ):
            raise InvalidRequestError(
                "Authorization requests for this client must use signed request objects.",
                state=request.payload.state,
            )

        # It MUST also reject the request if the Request Object uses an
        # alg value of none. If omitted, the default value is false.
        server_metadata = self.get_server_metadata()
        if (
            server_metadata
            and server_metadata.require_signed_request_object
            and request_object.header["alg"] == "none"
        ):
            raise InvalidRequestError(
                "Authorization requests for this server must use signed request objects.",
                state=request.payload.state,
            )

        # The client ID values in the client_id request parameter and in
        # the Request Object client_id claim MUST be identical.
        if request_object["client_id"] != request.payload.client_id:
            raise InvalidRequestError(
                "The 'client_id' claim from the request parameters "
                "and the request object claims don't match.",
                state=request.payload.state,
            )

        # The Request Object MAY be sent by value, as described in Section 5.1,
        # or by reference, as described in Section 5.2. request and
        # request_uri parameters MUST NOT be included in Request Objects.
        if "request" in request_object or "request_uri" in request_object:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters must not be included in the request object.",
                state=request.payload.state,
            )

        return request_object

    def get_request_object(self, request_uri: str) -> Optional[str]:
        """Download the request object at ``request_uri``.

        This method must be implemented if the ``request_uri`` parameter is supported::

            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def get_request_object(self, request_uri: str):
                    try:
                        return requests.get(request_uri).text
                    except requests.Exception:
                        return None
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client: ClientMixin):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def resolve_client_public_key(self, client):
                    if client.jwks_uri:
                        return requests.get(client.jwks_uri).json

                    return client.jwks
        """
        raise NotImplementedError()

    def get_server_metadata(self) -> AuthorizationServerMetadata:
        """Return server metadata which includes supported grant types,
        response types and etc.

        When the ``require_signed_request_object`` claim is :data:`True`,
        all clients require that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def get_server_metadata(self):
                    return AuthorizationServerMetadata({
                        "issuer": ...,
                        "authorization_endpoint": ...,
                        "require_signed_request_object": ...,
                    })

        """
        return AuthorizationServerMetadata()

    def get_client_metadata(self, client: ClientMixin) -> ClientMetadataClaims:
        """Return the 'require_signed_request_object' client metadata.

        When :data:`True`, the client requires that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def get_client_metadata(self):
                    return ClientMetadataClaims({
                        "require_signed_request_object": ...,
                    })

        If not implemented, the value is considered as :data:`False`.
        """
        return ClientMetadataClaims()


class JWTAuthenticationRequest:
    """Authorization server extension implementing the support
    for JWT secured authentication request, as defined in :rfc:`RFC9101 <9101>`.

    :param support_request: Whether to enable support for the ``request`` parameter.
    :param support_request_uri: Whether to enable support for the ``request_uri`` parameter.

    This extension is intended to be inherited and registered into the authorization server::

        class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
            def resolve_client_public_key(self, client: ClientMixin):
                return get_jwks_for_client(client)

            def get_request_object(self, request_uri: str):
                try:
                    return requests.get(request_uri).text
                except requests.Exception:
                    return None

            def get_server_metadata(self):
                return {
                    "issuer": ...,
                    "authorization_endpoint": ...,
                    "require_signed_request_object": ...,
                }

            def get_client_require_signed_request_object(self, client: ClientMixin):
                return client.require_signed_request_object


        authorization_server.register_extension(JWTAuthenticationRequest())
    """

    def __init__(self, support_request: bool = True, support_request_uri: bool = True):
        deprecate(
            "'JWTAuthenticationRequest' is deprecated in favor of 'JWTAuthorizationRequest'",
            version="1.8",
        )
        self.support_request = support_request
        self.support_request_uri = support_request_uri

    def __call__(self, authorization_server: AuthorizationServer):
        authorization_server.register_hook(
            "before_get_authorization_grant", self.parse_authorization_request
        )

    def parse_authorization_request(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        client = _validate_client(
            authorization_server.query_client, request.payload.client_id
        )
        if not self._shoud_proceed_with_request_object(
            authorization_server, request, client
        ):
            return

        raw_request_object = self._get_raw_request_object(authorization_server, request)
        request_object = self._decode_request_object(
            request, client, raw_request_object
        )
        payload = BasicOAuth2Payload(request_object)
        request.payload = payload

    def _shoud_proceed_with_request_object(
        self,
        authorization_server: AuthorizationServer,
        request: OAuth2Request,
        client: ClientMixin,
    ) -> bool:
        if "request" in request.payload.data and "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=request.payload.state,
            )

        if "request" in request.payload.data:
            if not self.support_request:
                raise RequestNotSupportedError(state=request.payload.state)
            return True

        if "request_uri" in request.payload.data:
            if not self.support_request_uri:
                raise RequestUriNotSupportedError(state=request.payload.state)
            return True

        # When the value of it [require_signed_request_object] as client metadata is true,
        # then the server MUST reject the authorization request
        # from the client that does not conform to this specification.
        if self.get_client_require_signed_request_object(client):
            raise InvalidRequestError(
                "Authorization requests for this client must use signed request objects.",
                state=request.payload.state,
            )

        # When the value of it [require_signed_request_object] as server metadata is true,
        # then the server MUST reject the authorization request
        # from any client that does not conform to this specification.
        metadata = self.get_server_metadata()
        if metadata and metadata.get("require_signed_request_object", False):
            raise InvalidRequestError(
                "Authorization requests for this server must use signed request objects.",
                state=request.payload.state,
            )

        return False

    def _get_raw_request_object(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ) -> str:
        if "request_uri" in request.payload.data:
            raw_request_object = self.get_request_object(
                request.payload.data["request_uri"]
            )
            if not raw_request_object:
                raise InvalidRequestUriError(state=request.payload.state)

        else:
            raw_request_object = request.payload.data["request"]

        return raw_request_object

    def _decode_request_object(
        self, request, client: ClientMixin, raw_request_object: str
    ):
        jwks = self.resolve_client_public_key(client)

        try:
            request_object = jwt.decode(raw_request_object, jwks)
            request_object.validate()

        except JoseError as error:
            raise InvalidRequestObjectError(
                description=error.description or InvalidRequestObjectError.description,
                state=request.payload.state,
            ) from error

        # It MUST also reject the request if the Request Object uses an
        # alg value of none when this server metadata value is true.
        # If omitted, the default value is false.
        if (
            self.get_client_require_signed_request_object(client)
            and request_object.header["alg"] == "none"
        ):
            raise InvalidRequestError(
                "Authorization requests for this client must use signed request objects.",
                state=request.payload.state,
            )

        # It MUST also reject the request if the Request Object uses an
        # alg value of none. If omitted, the default value is false.
        metadata = self.get_server_metadata()
        if (
            metadata
            and metadata.get("require_signed_request_object", False)
            and request_object.header["alg"] == "none"
        ):
            raise InvalidRequestError(
                "Authorization requests for this server must use signed request objects.",
                state=request.payload.state,
            )

        # The client ID values in the client_id request parameter and in
        # the Request Object client_id claim MUST be identical.
        if request_object["client_id"] != request.payload.client_id:
            raise InvalidRequestError(
                "The 'client_id' claim from the request parameters "
                "and the request object claims don't match.",
                state=request.payload.state,
            )

        # The Request Object MAY be sent by value, as described in Section 5.1,
        # or by reference, as described in Section 5.2. request and
        # request_uri parameters MUST NOT be included in Request Objects.
        if "request" in request_object or "request_uri" in request_object:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters must not be included in the request object.",
                state=request.payload.state,
            )

        return request_object

    def get_request_object(self, request_uri: str):
        """Download the request object at ``request_uri``.

        This method must be implemented if the ``request_uri`` parameter is supported::

            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def get_request_object(self, request_uri: str):
                    try:
                        return requests.get(request_uri).text
                    except requests.Exception:
                        return None
        """
        raise NotImplementedError()

    def resolve_client_public_keys(self, client: ClientMixin):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def resolve_client_public_key(self, client):
                    if client.jwks_uri:
                        return requests.get(client.jwks_uri).json

                    return client.jwks
        """
        raise NotImplementedError()

    def get_server_metadata(self) -> dict:
        """Return server metadata which includes supported grant types,
        response types and etc.

        When the ``require_signed_request_object`` claim is :data:`True`,
        all clients require that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "authorization_endpoint": ...,
                        "require_signed_request_object": ...,
                    }

        """
        return {}  # pragma: no cover

    def get_client_require_signed_request_object(self, client: ClientMixin) -> bool:
        """Return the 'require_signed_request_object' client metadata.

        When :data:`True`, the client requires that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

           class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
               def get_client_require_signed_request_object(self, client):
                   return client.require_signed_request_object

        If not implemented, the value is considered as :data:`False`.
        """
        return False  # pragma: no cover