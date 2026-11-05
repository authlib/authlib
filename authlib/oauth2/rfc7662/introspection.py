from ..rfc6749 import InvalidRequestError
from ..rfc6749 import JsonResponse
from ..rfc6749 import TokenEndpoint


class IntrospectionEndpoint(TokenEndpoint):
    """Implementation of introspection endpoint which is described in
    :rfc:`7662`.
    """

    #: Endpoint name to be registered
    ENDPOINT_NAME = "introspection"

    def authenticate_token(self, request, client):
        """The protected resource calls the introspection endpoint using an HTTP
        ``POST`` request with parameters sent as
        "application/x-www-form-urlencoded" data. The protected resource sends a
        parameter representing the token along with optional parameters
        representing additional context that is known by the protected resource
        to aid the authorization server in its response.

        token
            **REQUIRED**  The string value of the token. For access tokens, this
            is the ``access_token`` value returned from the token endpoint
            defined in OAuth 2.0. For refresh tokens, this is the
            ``refresh_token`` value returned from the token endpoint as defined
            in OAuth 2.0.

        token_type_hint
            **OPTIONAL**  A hint about the type of the token submitted for
            introspection.
        """
        self.check_params(request, client)
        # Per RFC 7662 §2.1, the server searches all its supported token types
        # when the hint does not help, so an unknown hint is ignored.
        hint = request.form.get("token_type_hint")
        if hint not in self.SUPPORTED_TOKEN_TYPES:
            hint = None

        token = self.query_token(request.form["token"], hint)
        if not token and hint is not None:
            token = self.query_token(request.form["token"], None)

        if token and self.check_permission(token, client, request):
            return token

    def check_params(self, request, client):
        params = request.form
        if "token" not in params:
            raise InvalidRequestError()

    def create_endpoint_response(self, request):
        """Validate introspection request and create the response.

        :returns: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`
        """
        # The authorization server first validates the client credentials
        client = self.authenticate_endpoint_client(request)

        # then verifies whether the token was issued to the client making
        # the revocation request
        token = self.authenticate_token(request, client)

        # the authorization server invalidates the token
        body = self.create_introspection_payload(token)
        return JsonResponse(body)

    def create_introspection_payload(self, token):
        # the token is not active, does not exist on this server, or the
        # protected resource is not allowed to introspect this particular
        # token, then the authorization server MUST return an introspection
        # response with the "active" field set to "false"
        if not token:
            return {"active": False}
        if token.is_expired() or token.is_revoked():
            return {"active": False}
        payload = self.introspect_token(token)
        if "active" not in payload:
            payload["active"] = True
        return payload

    def check_permission(self, token, client, request):
        """Check if the request has permission to introspect the token. Developers
        MUST implement this method::

            def check_permission(self, token, client, request):
                # only allow a special client to introspect the token
                return client.client_id == "introspection_client"

        :return: bool
        """
        raise NotImplementedError()

    def query_token(self, token_string, token_type_hint):
        """Get the token from database/storage by the given token string.
        Developers should implement this method::

            def query_token(self, token_string, token_type_hint):
                if token_type_hint == "access_token":
                    tok = Token.query_by_access_token(token_string)
                elif token_type_hint == "refresh_token":
                    tok = Token.query_by_refresh_token(token_string)
                else:
                    tok = Token.query_by_access_token(token_string)
                    if not tok:
                        tok = Token.query_by_refresh_token(token_string)
                return tok

        ``token_type_hint`` is ``None`` when the request has no hint or an
        unknown one. If no token is found with the hint, the endpoint calls
        this method again with ``None``.
        """
        raise NotImplementedError()

    def introspect_token(self, token):
        """Read given token and return its introspection metadata as a
        dictionary following :rfc:`7662#section-2.2`::

            def introspect_token(self, token):
                return {
                    "active": True,
                    "client_id": token.client_id,
                    "token_type": token.token_type,
                    "username": get_token_username(token),
                    "scope": token.get_scope(),
                    "sub": get_token_user_sub(token),
                    "aud": token.client_id,
                    "iss": "https://server.example.com/",
                    "exp": token.expires_at,
                    "iat": token.issued_at,
                }
        """
        raise NotImplementedError()
