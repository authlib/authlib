import hashlib
import json

from authlib.common.hooks import Hookable
from authlib.consts import default_json_headers
from authlib.deprecate import deprecate

from ..authenticate_client import _validate_client
from ..errors import InvalidRequestError
from ..errors import InvalidScopeError
from ..requests import OAuth2Request
from ..util import normalize_response_type

_UNSET = object()


class BaseGrant(Hookable):
    #: Allowed client auth methods for token endpoint
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic"]

    #: Designed for which "grant_type"
    GRANT_TYPE = None

    # NOTE: there is no charset for application/json, since
    # application/json should always in UTF-8.
    # The example on RFC is incorrect.
    # https://tools.ietf.org/html/rfc4627
    TOKEN_RESPONSE_HEADER = default_json_headers

    def __init__(self, request: OAuth2Request, server):
        super().__init__()
        #: The interactions the user must go through before the
        #: authorization response, in order, such as ``"login"`` or
        #: ``"consent"``. Extensions add theirs while the request is validated.
        self.interactions = []
        #: The :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`
        #: passed to ``get_consent_grant``, or ``None``.
        self.authorization_session = None
        #: Whether the request must be done without any user interaction,
        #: such as with the OpenID Connect ``prompt=none``. Its errors are
        #: then redirected even if the user is not logged in.
        self.silent = False
        self._deferred_error = None
        self._prompt = _UNSET
        self.redirect_uri = None
        self.request = request
        self.server = server

    @property
    def client(self):
        return self.request.client

    @property
    def prompt(self):
        """The first of the :attr:`interactions`, or ``None``."""
        if self._prompt is not _UNSET:
            return self._prompt

        return self.interactions[0] if self.interactions else None

    @prompt.setter
    def prompt(self, value):
        deprecate(
            "Setting 'grant.prompt' is deprecated. Read 'grant.interactions' "
            "instead, and keep your own values in your own attributes.",
            version="1.11",
        )
        self._prompt = value

    def generate_token(
        self,
        user=None,
        scope=None,
        grant_type=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        if grant_type is None:
            grant_type = self.GRANT_TYPE
        return self.server.generate_token(
            client=self.request.client,
            grant_type=grant_type,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )

    def authenticate_token_endpoint_client(self):
        """Authenticate client with the given methods for token endpoint.

        For example, the client makes the following HTTP request using TLS:

        .. code-block:: http

            POST /token HTTP/1.1
            Host: server.example.com
            Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
            Content-Type: application/x-www-form-urlencoded

            grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        Default available methods are: "none", "client_secret_basic" and
        "client_secret_post".

        :return: client
        """
        client = self.server.authenticate_client(
            self.request, self.TOKEN_ENDPOINT_AUTH_METHODS
        )
        self.server.send_signal("after_authenticate_client", client=client, grant=self)
        return client

    def save_token(self, token):
        """A method to save token into database."""
        return self.server.save_token(token, self.request)

    def validate_requested_scope(self):
        """Validate if requested scope is supported by Authorization Server."""
        scope = self.request.payload.scope
        return self.server.validate_requested_scope(scope)


class TokenEndpointMixin(Hookable):
    #: Allowed HTTP methods of this token endpoint
    TOKEN_ENDPOINT_HTTP_METHODS = ["POST"]

    #: Designed for which "grant_type"
    GRANT_TYPE = None

    @classmethod
    def check_token_endpoint(cls, request: OAuth2Request):
        return (
            request.payload.grant_type == cls.GRANT_TYPE
            and request.method in cls.TOKEN_ENDPOINT_HTTP_METHODS
        )

    def validate_token_request(self):
        raise NotImplementedError()

    def create_token_response(self):
        raise NotImplementedError()


class AuthorizationEndpointMixin(Hookable):
    RESPONSE_TYPES = set()
    ERROR_RESPONSE_FRAGMENT = False

    #: Where the authorization response parameters are added to the redirect
    #: URI. Per RFC 6749 §4.1.2, the authorization code goes in the query.
    RESPONSE_MODE = "query"

    #: The response mode chosen for this request, if it differs from
    #: ``RESPONSE_MODE``. Errors use it too.
    response_mode = None

    #: The authorization request parameters of this grant, with their JSON
    #: types. Per RFC 6749 §4.1.1 and §4.2.1.
    AUTHORIZATION_PARAMETERS = {
        "response_type": str,
        "client_id": str,
        "redirect_uri": str,
        "scope": str,
        "state": str,
    }

    _extension_authorization_parameters = {}

    @property
    def authorization_parameters(self):
        """The authorization request parameters of this grant, of its
        extensions and of the server extensions, with their JSON types."""
        return {
            **self.server.authorization_parameters,
            **self.AUTHORIZATION_PARAMETERS,
            **self._extension_authorization_parameters,
        }

    def register_authorization_parameters(self, parameters):
        """Add authorization request parameters to this grant. A grant
        extension calls it with the parameters it introduces::

            grant.register_authorization_parameters({"code_challenge": str})

        :param parameters: a dict of parameter names and JSON types
        """
        self._extension_authorization_parameters = {
            **self._extension_authorization_parameters,
            **parameters,
        }

    @classmethod
    def check_authorization_endpoint(cls, request: OAuth2Request):
        return normalize_response_type(request.payload.response_type) in {
            normalize_response_type(response_type)
            for response_type in cls.RESPONSE_TYPES
        }

    @staticmethod
    def validate_authorization_redirect_uri(request: OAuth2Request, client):
        if request.payload.redirect_uri:
            if not client.check_redirect_uri(request.payload.redirect_uri):
                raise InvalidRequestError(
                    f"Redirect URI {request.payload.redirect_uri} is not supported by client.",
                )
            return request.payload.redirect_uri
        else:
            redirect_uri = client.get_default_redirect_uri()
            if not redirect_uri:
                raise InvalidRequestError(
                    "Missing 'redirect_uri' in request.", state=request.payload.state
                )
            return redirect_uri

    def query_authorization_client(self):
        """Return the client of the authorization request.

        Per RFC 6749 §3.2.1, the client authenticates at the token endpoint,
        not at the authorization endpoint. Its ``token_endpoint_auth_method``
        does not matter here.

        :raises InvalidClientError: if ``client_id`` is missing or unknown
        """
        return _validate_client(
            self.server.query_client, self.request.payload.client_id
        )

    def validate_no_multiple_request_parameter(self, request: OAuth2Request):
        """For the Authorization Endpoint, request and response parameters MUST NOT be included
        more than once. Per :rfc:`6749#section-3.1`.

        It checks the parameters in :attr:`authorization_parameters`.
        """
        validate_no_repeated_parameter(request, self.authorization_parameters)

    def get_authorization_key(self):
        """Return a hash of the authorization request parameters.

        It is the same for all the HTTP requests of one authorization
        request, for instance before and after a login. The parameters that
        are not in :attr:`authorization_parameters`, such as the fields of a
        consent form, do not change it.
        """
        data = self.request.payload.data
        parameters = {
            name: data[name] for name in self.authorization_parameters if name in data
        }
        message = json.dumps(parameters, sort_keys=True)
        return hashlib.sha256(message.encode()).hexdigest()

    def validate_authorization_request_payload(self, redirect_uri):
        """Validate the requested scope of an authorization request."""
        self.validate_requested_scope()
        scope = self.request.client.get_allowed_scope(self.request.payload.scope)
        if scope is None:
            raise InvalidScopeError()
        self.request.scope = scope

    def validate_consent_request(self):
        redirect_uri = self.validate_authorization_request()
        self.redirect_uri = redirect_uri
        return redirect_uri

    def validate_interactions(self):
        """Check the :attr:`interactions` of the request.

        It runs after :meth:`validate_consent_request`, once the extensions
        have added their interactions. It adds ``"login"`` when the user is
        not logged in, unless the request is :attr:`silent`. It adds
        ``"consent"`` when the authorization session says that the user must
        give their consent. Extensions can also check the interactions here.
        """
        if (
            not self.request.user
            and not self.silent
            and "login" not in self.interactions
        ):
            index = 1 if self.interactions[:1] == ["create"] else 0
            self.interactions.insert(index, "login")

        session = self.authorization_session
        if (
            session is not None
            and self.request.user
            and "consent" not in self.interactions
            and session.is_consent_needed(self.request)
        ):
            self.interactions.append("consent")

    def validate_authorization_request(self):
        raise NotImplementedError()

    def create_authorization_response(self, redirect_uri: str, grant_user):
        raise NotImplementedError()


def validate_no_repeated_parameter(request: OAuth2Request, parameters):
    """Check that the request does not repeat one of the parameters.
    Per :rfc:`6749#section-3.1`.

    :param request: the authorization request
    :param parameters: the names of the parameters to check
    :raises InvalidRequestError: if a parameter is repeated
    """
    datalist = request.payload.datalist
    for param in parameters:
        if len(datalist.get(param, [])) > 1:
            raise InvalidRequestError(
                f"Multiple '{param}' in request.", state=request.payload.state
            )
