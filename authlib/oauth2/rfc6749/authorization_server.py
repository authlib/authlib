from functools import partial

from authlib.common.errors import ContinueIteration
from authlib.common.hooks import Hookable
from authlib.deprecate import deprecate

from .authenticate_client import ClientAuthentication
from .endpoint import Endpoint
from .endpoint import EndpointRequest
from .errors import InvalidScopeError
from .errors import OAuth2Error
from .errors import UnsupportedGrantTypeError
from .errors import UnsupportedResponseTypeError
from .grants.base import AuthorizationEndpointMixin
from .grants.base import validate_no_repeated_parameter
from .requests import JsonRequest
from .requests import OAuth2Request
from .responses import AuthorizationResponse
from .responses import JsonResponse
from .responses import OAuth2Response
from .responses import _encode_redirect
from .util import scope_to_list


class AuthorizationServer(Hookable):
    """Authorization server that handles Authorization Endpoint and Token
    Endpoint.

    :param scopes_supported: A list of supported scopes by this authorization server.
    """

    #: Per RFC 9700 §4.11.2, the server must authenticate the user before it
    #: redirects them. When the request of an anonymous user has an error
    #: for the redirect URI, :meth:`get_consent_grant` returns the grant with
    #: the ``"login"`` interaction instead of raising it. The error is raised
    #: after the login. An error without a grant, such as
    #: ``unsupported_response_type``, is not redirected. Silent requests,
    #: such as the OpenID Connect ``prompt=none``, are not concerned.
    defer_anonymous_errors = True

    def __init__(self, scopes_supported=None):
        super().__init__()
        self.scopes_supported = scopes_supported
        self._token_generators = {}
        self._client_auth = None
        self._authorization_grants = []
        self._token_grants = []
        self._endpoints = {}
        self._extensions = []
        self._authorization_parameters = {}

    def query_client(self, client_id):
        """Query OAuth client by client_id. The client model class MUST
        implement the methods described by
        :class:`~authlib.oauth2.rfc6749.ClientMixin`.
        """
        raise NotImplementedError()

    def save_token(self, token, request):
        """Define function to save the generated token into database."""
        raise NotImplementedError()

    def generate_token(
        self,
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        """Generate the token dict.

        :param grant_type: current requested grant_type.
        :param client: the client that making the request.
        :param user: current authorized user.
        :param expires_in: if provided, use this value as expires_in.
        :param scope: current requested scope.
        :param include_refresh_token: should refresh_token be included.
        :return: Token dict
        """
        # generator for a specified grant type
        func = self._token_generators.get(grant_type)
        if not func:
            # default generator for all grant types
            func = self._token_generators.get("default")
        if not func:
            raise RuntimeError("No configured token generator")

        return func(
            grant_type=grant_type,
            client=client,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )

    def register_token_generator(self, grant_type, func):
        """Register a function as token generator for the given ``grant_type``.
        Developers MUST register a default token generator with a special
        ``grant_type=default``::

            def generate_bearer_token(
                grant_type,
                client,
                user=None,
                scope=None,
                expires_in=None,
                include_refresh_token=True,
            ):
                token = {"token_type": "Bearer", "access_token": ...}
                if include_refresh_token:
                    token["refresh_token"] = ...
                ...
                return token


            authorization_server.register_token_generator(
                "default", generate_bearer_token
            )

        If you register a generator for a certain grant type, that generator will only works
        for the given grant type::

            authorization_server.register_token_generator(
                "client_credentials",
                generate_bearer_token,
            )

        :param grant_type: string name of the grant type
        :param func: a function to generate token
        """
        self._token_generators[grant_type] = func

    def authenticate_client(self, request, methods, endpoint="token"):
        """Authenticate client via HTTP request information with the given
        methods, such as ``client_secret_basic``, ``client_secret_post``.
        """
        if self._client_auth is None and self.query_client:
            self._client_auth = ClientAuthentication(self.query_client)
        return self._client_auth(request, methods, endpoint)

    def register_client_auth_method(self, method, func):
        """Add more client auth method. The default methods are:

        * none: The client is a public client and does not have a client secret
        * client_secret_post: The client uses the HTTP POST parameters
        * client_secret_basic: The client uses HTTP Basic

        :param method: Name of the Auth method
        :param func: Function to authenticate the client

        The auth method accept two parameters: ``query_client`` and ``request``,
        an example for this method::

            def authenticate_client_via_custom(query_client, request):
                client_id = request.headers["X-Client-Id"]
                client = query_client(client_id)
                do_some_validation(client)
                return client


            authorization_server.register_client_auth_method(
                "custom", authenticate_client_via_custom
            )
        """
        if self._client_auth is None and self.query_client:
            self._client_auth = ClientAuthentication(self.query_client)

        self._client_auth.register(method, func)

    def register_extension(self, extension):
        extension(self)
        self._extensions.append(extension)

    def register_authorization_parameters(self, parameters):
        """Add authorization request parameters to all the grants. A server
        extension calls it with the parameters it introduces::

            server.register_authorization_parameters({"response_mode": str})

        :param parameters: a dict of parameter names and JSON types
        """
        self._authorization_parameters.update(parameters)

    @property
    def authorization_parameters(self):
        """The authorization request parameters known before a grant is
        chosen, with their JSON types: those of RFC 6749 and of the server
        extensions."""
        return {
            **AuthorizationEndpointMixin.AUTHORIZATION_PARAMETERS,
            **self._authorization_parameters,
        }

    def get_error_uri(self, request, error):
        """Return a URI for the given error, framework may implement this method."""
        return None

    def send_signal(self, name, *args, **kwargs):
        """Framework integration can re-implement this method to support
        signal system.
        """
        raise NotImplementedError()

    def create_oauth2_request(self, request) -> OAuth2Request:
        """This method MUST be implemented in framework integrations. It is
        used to create an OAuth2Request instance.

        :param request: the "request" instance in framework
        :return: OAuth2Request instance
        """
        raise NotImplementedError()

    def create_json_request(self, request) -> JsonRequest:
        """This method MUST be implemented in framework integrations. It is
        used to create an HttpRequest instance.

        :param request: the "request" instance in framework
        :return: HttpRequest instance
        """
        raise NotImplementedError()

    def handle_response(self, status, body, headers):
        """Return HTTP response. Framework MUST implement this function."""
        raise NotImplementedError()

    def validate_requested_scope(self, scope):
        """Validate if requested scope is supported by Authorization Server.
        Developers CAN re-write this method to meet your needs.
        """
        if scope and self.scopes_supported:
            scopes = set(scope_to_list(scope))
            if not set(self.scopes_supported).issuperset(scopes):
                raise InvalidScopeError()

    def register_grant(self, grant_cls, extensions=None):
        """Register a grant class into the endpoint registry. Developers
        can implement the grants in ``authlib.oauth2.rfc6749.grants`` and
        register with this method::

            class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
                def authenticate_user(self, credential):
                    # ...

            authorization_server.register_grant(AuthorizationCodeGrant)

        :param grant_cls: a grant class.
        :param extensions: extensions for the grant class.
        """
        if hasattr(grant_cls, "check_authorization_endpoint"):
            self._authorization_grants.append((grant_cls, extensions))
        if hasattr(grant_cls, "check_token_endpoint"):
            self._token_grants.append((grant_cls, extensions))

    def register_endpoint(self, endpoint: type[Endpoint] | Endpoint):
        """Add extra endpoint to authorization server. e.g.
        RevocationEndpoint::

            authorization_server.register_endpoint(RevocationEndpoint)

        :param endpoint: An endpoint class or instance.
        """
        if isinstance(endpoint, type):
            endpoint = endpoint(self)
        else:
            endpoint.server = self

        endpoints = self._endpoints.setdefault(endpoint.ENDPOINT_NAME, [])
        endpoints.append(endpoint)

    def get_authorization_grant(self, request):
        """Find the authorization grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for grant_cls, extensions in self._authorization_grants:
            if grant_cls.check_authorization_endpoint(request):
                return _create_grant(grant_cls, extensions, request, self)

        # Per RFC 6749 §4.1.2.1, only redirect with the error if the client
        # exists and the redirect_uri has been validated against it.
        redirect_uri = None
        if client_id := request.payload.client_id:
            if client := self.query_client(client_id):
                request.client = client
                if requested_uri := request.payload.redirect_uri:
                    if client.check_redirect_uri(requested_uri):
                        redirect_uri = requested_uri
                else:
                    redirect_uri = client.get_default_redirect_uri()

        raise UnsupportedResponseTypeError(
            f"The response type '{request.payload.response_type}' is not supported by the server.",
            request.payload.response_type,
            redirect_uri=redirect_uri,
        )

    def get_consent_grant(self, request=None, end_user=None, session=None):
        """Validate current HTTP request for authorization page. This page
        is designed for resource owner to grant or deny the authorization.

        :param request: HTTP request instance
        :param end_user: the logged-in user, or ``None``
        :param session: an
            :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`. Its
            user replaces ``end_user``.
        :raises ValueError: if ``end_user`` is not the user of ``session``
        """
        request = self.create_oauth2_request(request)
        if session is not None:
            user = session.get_user()
            if end_user is not None and end_user != user:
                raise ValueError("'end_user' is not the user of the 'session'.")

            end_user = user

        grant = None
        try:
            request.user = end_user
            validate_no_repeated_parameter(request, self.authorization_parameters)

            grant = self.get_authorization_grant(request)
            grant.authorization_session = session
            grant.validate_no_multiple_request_parameter(request)
            request.authorization_key = grant.get_authorization_key()
            if session is not None:
                request._request_time_loader = partial(_load_request_time, grant)

            grant.validate_consent_request()
            grant.validate_interactions()
            if grant.interactions:
                _keep_request_time(request)

        except OAuth2Error as error:
            # REQUIRED if a "state" parameter was present in the client
            # authorization request.  The exact value received from the
            # client.
            error.state = request.payload.state
            _set_error_response_mode(error, grant)
            if self._is_deferred(request, grant, error):
                error.redirect_uri = None
                if grant is not None:
                    grant.interactions = ["login"]
                    grant._deferred_error = error
                    _keep_request_time(request)
                    return grant

            if session is not None:
                session.end_request(request)

            _check_error_redirect(session, request, error)
            raise

        except Exception:
            if session is not None:
                session.end_request(request)

            raise

        return grant

    def _is_deferred(self, request, grant, error):
        """Tell if an error must wait for the login of the user before it is
        redirected. Per RFC 9700 §4.11.2."""
        return (
            self.defer_anonymous_errors
            and error.redirect_uri is not None
            and not request.user
            and (grant is None or not grant.silent)
        )

    def get_token_grant(self, request):
        """Find the token grant for current request.

        :param request: OAuth2Request instance.
        :return: grant instance
        """
        for grant_cls, extensions in self._token_grants:
            if grant_cls.check_token_endpoint(request):
                return _create_grant(grant_cls, extensions, request, self)
        raise UnsupportedGrantTypeError(request.payload.grant_type)

    def validate_endpoint_request(self, name, request=None) -> EndpointRequest:
        """Validate endpoint request and return the validated request object.

        Use this for interactive endpoints where you need to handle UI
        between validation and response creation.

        :param name: Endpoint name
        :param request: HTTP request instance
        :returns: Validated EndpointRequest object
        :raises OAuth2Error: If validation fails
        :raises RuntimeError: If endpoint not found

        Example::

            req = server.validate_endpoint_request("end_session")
            if req.needs_confirmation:
                return render_template("confirm_logout.html", ...)
            return server.create_endpoint_response("end_session", req)
        """
        if name not in self._endpoints:
            raise RuntimeError(f"There is no '{name}' endpoint.")

        endpoint = self._endpoints[name][0]
        request = endpoint.create_endpoint_request(request)
        return endpoint.validate_request(request)

    def create_endpoint_response(self, name, request=None):
        """Validate endpoint request and create endpoint response.

        Can be called with:
        - A raw HTTP request or None: validates and responds in one step
        - A validated EndpointRequest: skips validation, creates response directly

        :param name: Endpoint name
        :param request: HTTP request instance or validated EndpointRequest
        :return: Response, or None if the endpoint returns None
        """
        if name not in self._endpoints:
            raise RuntimeError(f"There is no '{name}' endpoint.")

        endpoints = self._endpoints[name]

        # If request is already validated, create response directly
        if isinstance(request, EndpointRequest):
            endpoint = endpoints[0]
            try:
                result = endpoint.create_response(request)
                if result is None:
                    return None
                return self._send_response(result)
            except OAuth2Error as error:
                return self.handle_error_response(request.request, error)

        # Otherwise, validate and respond (existing behavior)
        for endpoint in endpoints:
            try:
                request = endpoint.create_endpoint_request(request)
                result = endpoint(request)
                if result is None:
                    return None
                return self._send_response(result)
            except ContinueIteration:
                continue
            except OAuth2Error as error:
                return self.handle_error_response(request, error)

    def create_authorization_response(self, request=None, grant_user=None, grant=None):
        """Validate authorization request and create authorization response.

        :param request: HTTP request instance.
        :param grant_user: if granted, it is resource owner. If denied,
            it is None.
        :param grant: the grant returned by :meth:`get_consent_grant`
        :returns: Response
        :raises TypeError: without ``grant``
        :raises ValueError: if ``grant_user`` is not the user of the
            authorization session

        When :meth:`get_consent_grant` deferred an error until the login of
        the user, the error is returned without redirection.
        """
        if grant is None:
            raise TypeError(
                "create_authorization_response() requires the 'grant' returned "
                "by get_consent_grant()."
            )

        session = grant.authorization_session
        try:
            if session is not None and grant_user is not None:
                if grant_user != grant.request.user:
                    raise ValueError(
                        "'grant_user' is not the user of the authorization session."
                    )

            try:
                if not isinstance(request, OAuth2Request):
                    request = self.create_oauth2_request(request)
            except OAuth2Error as error:
                response = self.handle_error_response(request, error)
            else:
                response = self._create_grant_response(request, grant, grant_user)

            grant.execute_hook("after_authorization_response", response)
        finally:
            if session is not None:
                session.end_request(grant.request)

        return response

    def _create_grant_response(self, request, grant, grant_user):
        """Return the authorization response of a grant, or its error."""
        if grant._deferred_error is not None:
            return self.handle_error_response(request, grant._deferred_error)

        try:
            redirect_uri = grant.validate_authorization_request()
            result = grant.create_authorization_response(redirect_uri, grant_user)
            return self._send_response(result)
        except OAuth2Error as error:
            error.state = grant.request.payload.state
            _set_error_response_mode(error, grant)
            _check_error_redirect(grant.authorization_session, grant.request, error)
            return self.handle_error_response(request, error)

    def create_token_response(self, request=None):
        """Validate token request and create token response.

        :param request: HTTP request instance
        """
        try:
            request = self.create_oauth2_request(request)
            grant = self.get_token_grant(request)
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

        try:
            grant.validate_token_request()
            return self._send_response(grant.create_token_response())
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

    def encode_response(self, response):
        """Turn a response into the arguments of :meth:`handle_response`.

        :param response: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`
        :return: ``(status_code, body, headers)``
        """
        if isinstance(response, AuthorizationResponse):
            response = self.encode_authorization_response(response)

        return response.status_code, response.body, response.headers

    def encode_authorization_response(self, response):
        """Encode an authorization response according to its response mode.

        :param response: an :class:`~authlib.oauth2.rfc6749.AuthorizationResponse`
        :return: an :class:`~authlib.oauth2.rfc6749.OAuth2Response`
        :raises ValueError: if the response mode is not supported
        """
        return _encode_redirect(response)

    def handle_error_response(self, request, error):
        if error.redirect_uri:
            response_mode = error.response_mode or (
                "fragment" if error.redirect_fragment else "query"
            )
            response = AuthorizationResponse(
                error.redirect_uri, error.get_body(), response_mode
            )
            return self._send_response(response)

        status_code, body, headers = error(self.get_error_uri(request, error))
        response = JsonResponse(body, status_code=status_code, headers=headers)
        return self._send_response(response)

    def _send_response(self, result):
        """Send a response, or a legacy ``(status_code, body, headers)`` tuple."""
        if not isinstance(result, OAuth2Response):
            deprecate(
                "Returning a '(status_code, body, headers)' tuple from a grant "
                "or an endpoint is deprecated. Return an 'OAuth2Response' instead.",
                version="1.11",
            )
            result = OAuth2Response(*result)
        return self.handle_response(*self.encode_response(result))


def _set_error_response_mode(error, grant):
    """Send the error with the response mode chosen for the request."""
    if error.response_mode is None:
        error.response_mode = getattr(grant, "response_mode", None)


def _create_grant(grant_cls, extensions, request, server):
    grant = grant_cls(request, server)
    if extensions:
        for ext in extensions:
            ext(grant)
    return grant


def _check_error_redirect(session, request, error):
    """Return the error without redirection when the authorization session
    does not trust the redirect URI."""
    if (
        error.redirect_uri is not None
        and session is not None
        and not session.can_redirect_error(request, error)
    ):
        error.redirect_uri = None


def _load_request_time(grant, request):
    """Read the start time of the request from the authorization session,
    unless the request is silent."""
    if grant.silent:
        return None

    return grant.authorization_session.get_request_time(request)


def _keep_request_time(request):
    """Read the start time of the request from the authorization session, so
    that the session keeps it until the user comes back from the
    interactions."""
    return request.request_time
