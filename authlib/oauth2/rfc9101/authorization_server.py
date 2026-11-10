from joserfc import jwt
from joserfc.errors import DecodeError
from joserfc.errors import JoseError
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import audience_matches
from authlib._joserfc_helpers import import_any_key

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import ClientMixin
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from .errors import InvalidRequestObjectError
from .errors import InvalidRequestUriError
from .errors import RequestNotSupportedError
from .errors import RequestUriNotSupportedError


class _RequestObjectPayload(BasicOAuth2Payload):
    """The authorization request parameters of a request object."""


class JWTAuthenticationRequest:
    """Authorization server extension implementing the support
    for JWT secured authentication request, as defined in :rfc:`RFC9101 <9101>`.

    :param support_request: Whether to enable support for the ``request`` parameter.
    :param support_request_uri: Whether to enable support for the ``request_uri`` parameter.

    This extension is intended to be inherited and registered into the authorization server::

        class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
            def resolve_client_public_key(self, client: ClientMixin):
                return get_jwks_for_client(client)

            def validate_request_uri(self, request_uri: str, client: ClientMixin):
                return is_approved_request_uri(request_uri, client)

            def get_request_object(self, request_uri: str):
                # Apply the retrieval safeguards documented in get_request_object.
                return fetch_approved_request_object(request_uri)

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

    claims_validator = jwt.JWTClaimsRegistry(
        client_id={"essential": True},
    )

    def __init__(self, support_request: bool = True, support_request_uri: bool = True):
        self.support_request = support_request
        self.support_request_uri = support_request_uri

    def __call__(self, authorization_server: AuthorizationServer):
        authorization_server.register_authorization_parameters(
            {"request": str, "request_uri": str}
        )
        authorization_server.register_hook(
            self.parse_authorization_request,
            before=AuthorizationServer.get_authorization_grant,
        )
        authorization_server.register_hook(
            self.validate_grant_parameter_types,
            after=AuthorizationServer.get_authorization_grant,
        )

    def get_request_object_signing_algorithms(self, client):
        """Return the supported algorithms for verifying the ``request_object`` JWT signature.
        By default, this method will only return the recommended algorithms. If signed request
        object is not required, "none" algorithm will be included. The signature
        requirement is enforced independently, even if this method returns "none".

        Developers can override this method to customize the supported algorithms::

            def get_request_object_signing_algorithms(self, client):
                return ["RS256"]
        """
        metadata = self.get_server_metadata()
        algorithms = metadata.get("request_object_signing_alg_values_supported")
        if not algorithms:
            require_signed1 = self.get_client_require_signed_request_object(client)
            require_signed2 = metadata.get("require_signed_request_object", False)
            if require_signed1 or require_signed2:
                algorithms = JWSRegistry.recommended
            else:
                algorithms = [*JWSRegistry.recommended, "none"]
        return algorithms

    def parse_authorization_request(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        client_id = request.payload.client_id
        if client_id is None:
            raise InvalidClientError(
                status_code=404,
                description="Missing 'client_id' parameter.",
            )

        client = authorization_server.query_client(client_id)
        if not client:
            raise InvalidClientError(
                status_code=404,
                description="The client does not exist on this server.",
            )

        if not self._shoud_proceed_with_request_object(request, client):
            return

        raw_request_object = self._get_raw_request_object(request, client)
        request_object = self._decode_request_object(
            request, client, raw_request_object
        )
        _validate_parameter_types(
            request_object.claims,
            authorization_server.authorization_parameters,
            request.payload.state,
        )
        request.payload = _RequestObjectPayload(request_object.claims)

    def validate_grant_parameter_types(self, authorization_server, grant):
        """Check the JSON types of the request object parameters that the
        grant and its extensions declare.

        :param authorization_server: the authorization server
        :param grant: the grant chosen for the authorization request
        :raises InvalidRequestObjectError: if a parameter has an invalid type
        """
        payload = grant.request.payload
        if isinstance(payload, _RequestObjectPayload):
            _validate_parameter_types(
                payload.data, grant.authorization_parameters, payload.state
            )

    def _shoud_proceed_with_request_object(
        self,
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
        self, request: OAuth2Request, client: ClientMixin
    ) -> str:
        if "request_uri" in request.payload.data:
            request_uri = request.payload.data["request_uri"]
            if not request_uri or not self.validate_request_uri(request_uri, client):
                raise InvalidRequestUriError(state=request.payload.state)
            raw_request_object = self.get_request_object(request_uri)
            if not raw_request_object:
                raise InvalidRequestUriError(state=request.payload.state)

        else:
            raw_request_object = request.payload.data["request"]

        return raw_request_object

    def _decode_request_object(
        self, request, client: ClientMixin, raw_request_object: str
    ):
        jwks = self.resolve_client_public_key(client)
        key = import_any_key(jwks)
        algorithms = self.get_request_object_signing_algorithms(client)
        metadata = self.get_server_metadata() or {}
        if self.get_client_require_signed_request_object(client) or metadata.get(
            "require_signed_request_object", False
        ):
            # Algorithm customization must not weaken the signature requirement.
            algorithms = [algorithm for algorithm in algorithms if algorithm != "none"]

        try:
            if not algorithms:
                raise UnsupportedAlgorithmError()
            request_object = jwt.decode(raw_request_object, key, algorithms=algorithms)
            self.claims_validator.validate(request_object.claims)
        except UnsupportedAlgorithmError as error:
            raise InvalidRequestError(
                "Authorization requests must be signed with supported algorithms.",
                state=request.payload.state,
            ) from error
        except DecodeError as error:
            raise InvalidRequestObjectError(state=request.payload.state) from error
        except JoseError as error:
            raise InvalidRequestObjectError(
                description=error.description or InvalidRequestObjectError.description,
                state=request.payload.state,
            ) from error

        # The client ID values in the client_id request parameter and in
        # the Request Object client_id claim MUST be identical.
        if request_object.claims["client_id"] != request.payload.client_id:
            raise InvalidRequestError(
                "The 'client_id' claim from the request parameters "
                "and the request object claims don't match.",
                state=request.payload.state,
            )

        # Per RFC 7519 §4.1.3, if the principal processing the claim does not
        # identify itself with a value in the "aud" claim when this claim is
        # present, then the JWT MUST be rejected.
        if "aud" in request_object.claims and not audience_matches(
            request_object.claims["aud"], self.get_audiences()
        ):
            raise InvalidRequestObjectError(
                description="The 'aud' claim does not identify this server.",
                state=request.payload.state,
            )

        # The Request Object MAY be sent by value, as described in Section 5.1,
        # or by reference, as described in Section 5.2. request and
        # request_uri parameters MUST NOT be included in Request Objects.
        if "request" in request_object.claims or "request_uri" in request_object.claims:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters must not be included in the request object.",
                state=request.payload.state,
            )

        return request_object

    def validate_request_uri(self, request_uri: str, client: ClientMixin) -> bool:
        """Return whether ``request_uri`` may be retrieved for this client.

        Called before :meth:`get_request_object`. The default rejects every URI;
        applications supporting ``request_uri`` must implement a secure policy.
        For network retrieval, prevent SSRF, including private destinations and
        DNS rebinding. For references to locally stored request objects, validate
        that the object belongs to the requesting client.

        OIDC URI registration is handled by
        :class:`authlib.oidc.core.JWTAuthenticationRequest` independently of this
        application policy.
        """
        return False

    def get_request_object(self, request_uri: str):
        """Retrieve the request object at an approved ``request_uri``.

        This method must be implemented if ``request_uri`` is supported.
        For network retrieval, enforce HTTPS and restrict outbound connections
        to approved public destinations, including the resolved IP addresses.
        Do not follow redirects. Limit response size and retrieval time, and
        check the response media type, as described in :rfc:`9101` Section 10.4.1.

        The authorization view usually calls ``get_consent_grant`` twice, to
        show the consent page and to handle the answer of the user. Each call
        fetches the request object again, and the client can return a
        different one the second time. See :ref:`jar-consent-retention`.

        The following example adds HTTP response safeguards. The application's
        HTTP transport or network policy must also block private destinations
        and prevent DNS rebinding::

            def get_request_object(self, request_uri: str):
                try:
                    with requests.get(
                        request_uri,
                        timeout=(3, 5),
                        allow_redirects=False,
                        stream=True,
                        headers={"Accept": "application/oauth-authz-req+jwt"},
                    ) as response:
                        media_type = response.headers.get("Content-Type", "").split(
                            ";", 1
                        )[0]
                        if (
                            response.status_code != 200
                            or media_type != "application/oauth-authz-req+jwt"
                        ):
                            return None
                        content = bytearray()
                        for chunk in response.iter_content(chunk_size=4096):
                            content.extend(chunk)
                            if len(content) > 262144:
                                return None
                        return content.decode("utf-8")
                except (requests.RequestException, UnicodeError):
                    return None

        A timeout between reads is not an overall deadline. Also enforce an
        overall retrieval deadline in the transport or application.
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client: ClientMixin):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            from joserfc import KeySet


            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def resolve_client_public_key(self, client):
                    if client.jwks_uri:
                        data = requests.get(client.jwks_uri).json()
                        return KeySet.import_key_set(data)

                    return KeySet.import_key_set(client.jwks)
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
                        "request_object_signing_alg_values_supported": ["RS256", ...],
                    }

        """
        return {}  # pragma: no cover

    def get_audiences(self) -> list[str]:
        """Return the accepted values of the request object ``aud`` claim.

        A request object with an ``aud`` claim is rejected when ``aud`` does not
        contain one of these values. A request object without ``aud`` is
        accepted. By default, it returns the ``issuer`` of
        :meth:`get_server_metadata`, or an empty list when there is none.
        Developers MAY re-implement it in subclass, for example to also accept
        the authorization endpoint URL::

            def get_audiences(self):
                metadata = self.get_server_metadata()
                return [metadata["issuer"], metadata["authorization_endpoint"]]

        :return: list of strings
        """
        issuer = (self.get_server_metadata() or {}).get("issuer")
        return [issuer] if issuer else []

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


def _validate_parameter_types(claims, parameters, state):
    """Check the JSON types of the request object parameters."""
    # RFC 9101 §4: parameter names and string values MUST be included as
    # JSON strings. Numerical values MUST be included as JSON numbers.
    for name, expected_type in parameters.items():
        if name not in claims:
            continue

        value = claims[name]
        if isinstance(value, bool) or not isinstance(value, expected_type):
            raise InvalidRequestObjectError(
                description=f"The '{name}' parameter has an invalid type.",
                state=state,
            )
