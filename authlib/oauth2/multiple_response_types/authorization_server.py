from ..rfc6749 import AuthorizationServer
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Error

DEFAULT_RESPONSE_MODES = ["query", "fragment"]


class ResponseMode:
    """A response mode for :class:`MultipleResponseTypes`, besides ``query``
    and ``fragment``. Subclasses encode the authorization responses::

        class MyResponseMode(ResponseMode):
            RESPONSE_MODES = ["my_mode"]

            def encode(self, response):
                return OAuth2Response(200, render(response), headers)


        server.register_extension(MultipleResponseTypes([MyResponseMode()]))
    """

    #: The ``response_mode`` values that this class encodes.
    RESPONSE_MODES = []

    def validate(self, grant, redirect_uri):
        """Check that the authorization request can use this response mode.

        :param grant: the grant that validates the authorization request
        :param redirect_uri: the redirect URI of the authorization request
        :raises OAuth2Error: if the request cannot use this response mode
        """

    def encode(self, response):
        """Encode an authorization response.

        :param response: an :class:`~authlib.oauth2.rfc6749.AuthorizationResponse`
        :return: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`
        """
        raise NotImplementedError()


class MultipleResponseTypes:
    """Authorization server extension for OAuth 2.0 Multiple Response Type
    Encoding Practices. Clients choose how they receive the authorization
    responses with the ``response_mode`` parameter::

        server.register_extension(MultipleResponseTypes())

    The server accepts the modes of its ``response_modes_supported`` metadata.
    Override :meth:`get_server_metadata` to return them.

    :param response_modes: a list of :class:`ResponseMode` for the modes
        besides ``query`` and ``fragment``
    """

    def __init__(self, response_modes=None):
        self.response_modes = {
            name: response_mode
            for response_mode in response_modes or []
            for name in response_mode.RESPONSE_MODES
        }

    def __call__(self, authorization_server):
        authorization_server.register_authorization_parameters({"response_mode": str})
        authorization_server.register_hook(
            self.resolve_response_mode,
            after=AuthorizationServer.get_authorization_grant,
        )
        authorization_server.register_hook(
            self.encode_authorization_response,
            replace=AuthorizationServer.encode_authorization_response,
        )

    def get_server_metadata(self):
        """Return the server metadata. The ``response_modes_supported`` value
        sets the accepted response modes. It defaults to ``query`` and
        ``fragment``, per RFC 8414 §2::

            def get_server_metadata(self):
                return {"response_modes_supported": ["query", "fragment"]}

        :return: a dict of server metadata
        """
        return {}

    def get_supported_response_modes(self):
        """Return the response modes that the server accepts and can encode."""
        metadata = self.get_server_metadata()
        supported = metadata.get("response_modes_supported", DEFAULT_RESPONSE_MODES)
        encoded = set(DEFAULT_RESPONSE_MODES) | set(self.response_modes)
        return [
            response_mode for response_mode in supported if response_mode in encoded
        ]

    def check_response_mode(self, grant, response_mode):
        """Check that the request of a grant can use a response mode.

        Per OAuth 2.0 Multiple Response Type Encoding Practices §7, access
        tokens and ID tokens MUST NOT be encoded in the query string.

        :param grant: the grant of the authorization request
        :param response_mode: the requested ``response_mode``
        :return: bool
        """
        if response_mode not in self.get_supported_response_modes():
            return False

        if response_mode != "query":
            return True

        response_types = set(grant.request.payload.response_type.split())
        return not response_types & {"token", "id_token"}

    def resolve_response_mode(self, authorization_server, grant):
        """Validate the requested response mode with the authorization request."""
        grant.register_hook(
            self.validate_response_mode, after=grant.validate_authorization_request
        )

    def validate_response_mode(self, grant, redirect_uri):
        """Use the requested response mode for the responses and the errors,
        once the request can use it. Until then, errors use the default
        response mode of the grant. Without a requested response mode, use
        the default one, once the request can use it.

        :raises InvalidRequestError: if the request cannot use the requested
            response mode
        """
        response_mode = grant.request.payload.data.get("response_mode")
        if response_mode is None:
            self.validate_default_response_mode(grant, redirect_uri)
            grant.response_mode = grant.RESPONSE_MODE
            return

        try:
            if not self.check_response_mode(grant, response_mode):
                raise InvalidRequestError(
                    "The 'response_mode' value is not supported for this response type.",
                    redirect_uri=redirect_uri,
                )

            if response_mode in self.response_modes:
                self.response_modes[response_mode].validate(grant, redirect_uri)

        except OAuth2Error as error:
            if error.response_mode is None:
                self.validate_default_response_mode(grant, redirect_uri)
                error.response_mode = grant.RESPONSE_MODE

            raise

        grant.response_mode = response_mode

    def validate_default_response_mode(self, grant, redirect_uri):
        """Check that the request can use the default response mode of the
        grant.

        :raises RuntimeError: if nothing encodes the default response mode
        :raises OAuth2Error: if the request cannot use it
        """
        if grant.RESPONSE_MODE in DEFAULT_RESPONSE_MODES:
            return

        if grant.RESPONSE_MODE not in self.response_modes:
            raise RuntimeError(
                f"The {grant.RESPONSE_MODE!r} response mode of "
                f"{type(grant).__name__} needs a ResponseMode in MultipleResponseTypes."
            )

        self.response_modes[grant.RESPONSE_MODE].validate(grant, redirect_uri)

    def encode_authorization_response(self, authorization_server, original, response):
        """Encode the responses of the response modes besides ``query`` and
        ``fragment``.
        """
        response_mode = self.response_modes.get(response.response_mode)
        if response_mode is None:
            return original(response)

        return response_mode.encode(response)
