from ..rfc6749 import InvalidGrantError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import JsonResponse
from ..rfc6749 import TokenEndpoint


class RevocationEndpoint(TokenEndpoint):
    """Implementation of revocation endpoint which is described in
    :rfc:`7009`.
    """

    #: Endpoint name to be registered
    ENDPOINT_NAME = "revocation"

    def authenticate_token(self, request, client):
        """The client constructs the request by including the following
        parameters using the "application/x-www-form-urlencoded" format in
        the HTTP request entity-body:

        token
            REQUIRED.  The token that the client wants to get revoked.

        token_type_hint
            OPTIONAL.  A hint about the type of the token submitted for
            revocation.
        """
        self.check_params(request, client)
        # Per RFC 7009 §2.2, an invalid token type hint value is ignored.
        hint = request.form.get("token_type_hint")
        if hint not in self.SUPPORTED_TOKEN_TYPES:
            hint = None

        token = self.query_token(request.form["token"], hint)
        # Per RFC 7009 §2.1, the search is extended to all supported token
        # types when the token is not found with the hint.
        if not token and hint is not None:
            token = self.query_token(request.form["token"], None)

        if token and not token.check_client(client):
            raise InvalidGrantError()
        return token

    def check_params(self, request, client):
        if "token" not in request.form:
            raise InvalidRequestError()

    def create_endpoint_response(self, request):
        """Validate revocation request and create the response for revocation.
        For example, a client may request the revocation of a refresh token
        with the following request::

            POST /revoke HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

            token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token

        :returns: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`
        """
        # The authorization server first validates the client credentials
        client = self.authenticate_endpoint_client(request)

        # then verifies whether the token was issued to the client making
        # the revocation request
        token = self.authenticate_token(request, client)

        # the authorization server invalidates the token
        if token:
            self.revoke_token(token, request)
            self.server.send_signal(
                "after_revoke_token",
                token=token,
                client=client,
            )
        return JsonResponse({})

    def query_token(self, token_string, token_type_hint):
        """Get the token from database/storage by the given token string.
        Developers should implement this method::

            def query_token(self, token_string, token_type_hint):
                if token_type_hint == 'access_token':
                    return Token.query_by_access_token(token_string)
                if token_type_hint == 'refresh_token':
                    return Token.query_by_refresh_token(token_string)
                return Token.query_by_access_token(token_string) or \
                    Token.query_by_refresh_token(token_string)

        ``token_type_hint`` is ``None`` when the request has no hint or an
        unknown one. If no token is found with the hint, the endpoint calls
        this method again with ``None``.
        """
        raise NotImplementedError()

    def revoke_token(self, token, request):
        """Mark token as revoked. Since token MUST be unique, it would be
        dangerous to delete it. Consider this situation:

        1. Jane obtained a token XYZ
        2. Jane revoked (deleted) token XYZ
        3. Bob generated a new token XYZ
        4. Jane can use XYZ to access Bob's resource

        It would be secure to mark a token as revoked::

            def revoke_token(self, token, request):
                token.access_token_revoked = True
                if request.form["token"] != token.access_token:
                    token.refresh_token_revoked = True
                token.save()

        Per :rfc:`7009#section-2.1`, revoking a refresh token should also
        invalidate the access token. The hint may not match the presented
        token, so check the presented token instead of the hint.
        """
        raise NotImplementedError()
