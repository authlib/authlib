from ..rfc6749 import AccessDeniedError
from ..rfc6749 import AuthorizationResponse
from ..rfc6749.grants import BaseGrant
from ..rfc6749.grants.authorization_code import validate_code_authorization_request
from ..rfc6749.grants.base import AuthorizationEndpointMixin


class NoneResponseTypeGrant(BaseGrant, AuthorizationEndpointMixin):
    """The ``none`` response type. The user grants or denies the request, and
    the client receives no code and no token::

        server.register_grant(NoneResponseTypeGrant)

    Per OAuth 2.0 Multiple Response Type Encoding Practices §4, the response
    contains ``state``, and no code or token.
    """

    RESPONSE_TYPES = {"none"}

    #: Per OAuth 2.0 Multiple Response Type Encoding Practices §4, the default
    #: response mode is the query response mode.
    RESPONSE_MODE = "query"

    def validate_authorization_request(self):
        """Validate the client, the redirect URI and the scope of the request.

        :return: the redirect URI
        """
        return validate_code_authorization_request(self)

    def create_authorization_response(self, redirect_uri, grant_user):
        """Redirect the user to the client, with ``state`` if the request has
        one.

        :param redirect_uri: the redirect URI of the request
        :param grant_user: the user, or *None* if the user denied the request
        :return: an :class:`~authlib.oauth2.rfc6749.AuthorizationResponse`
        :raises AccessDeniedError: if the user denied the request
        """
        if not grant_user:
            raise AccessDeniedError(redirect_uri=redirect_uri)

        self.request.user = grant_user
        params = []
        if self.request.payload.state:
            params.append(("state", self.request.payload.state))

        return AuthorizationResponse(
            redirect_uri, params, self.response_mode or self.RESPONSE_MODE
        )
