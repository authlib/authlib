"""OpenID Connect RP-Initiated Logout 1.0 implementation.

https://openid.net/specs/openid-connect-rpinitiated-1_0.html
"""

from typing import Optional

from authlib.common.urls import add_params_to_uri
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.errors import InvalidRequestError


class EndSessionEndpoint:
    """OpenID Connect RP-Initiated Logout Endpoint.

    This endpoint allows a Relying Party to request that an OpenID Provider
    log out the End-User. It must be subclassed and Developers
    MUST implement the missing methods::

        from authlib.oidc.rpinitiated import EndSessionEndpoint


        class MyEndSessionEndpoint(EndSessionEndpoint):
            def get_client_by_id(self, client_id):
                return Client.query.filter_by(client_id=client_id).first()

            def get_server_jwks(self):
                return server_jwks().as_dict()

            def validate_id_token_claims(self, id_token_claims):
                # Validate that the token corresponds to an active session
                if id_token_claims["sid"] not in current_sessions(
                    id_token_claims["aud"]
                ):
                    return False
                return True

            def end_session(self, request, id_token_claims):
                # Perform actual session termination
                logout_user()

            def create_end_session_response(self, request):
                # Create the response after successful logout
                # when there is no valid redirect uri
                return 200, "You have been logged out.", []

            def create_confirmation_response(
                self, request, client, redirect_uri, ui_locales
            ):
                # Create a page asking the user to confirm logout
                return (
                    200,
                    render_confirmation_page(
                        client=client,
                        redirect_uri=redirect_uri,
                        state=state,
                        ui_locales=ui_locales,
                    ),
                    [("Content-Type", "text/html")],
                )

    Register this endpoint and use it in routes::

        authorization_server.register_endpoint(MyEndSessionEndpoint())


        # for Flask
        @app.route("/oauth/end_session", methods=["GET", "POST"])
        def end_session():
            return authorization_server.create_endpoint_response("end_session")


        # for Django
        from django.views.decorators.http import require_http_methods


        @require_http_methods(["GET", "POST"])
        def end_session(request):
            return authorization_server.create_endpoint_response("end_session", request)
    """

    ENDPOINT_NAME = "end_session"

    def __init__(self, server=None):
        self.server = server

    def create_endpoint_request(self, request: OAuth2Request):
        return self.server.create_oauth2_request(request)

    def __call__(self, request: OAuth2Request):
        data = request.payload.data
        id_token_hint = data.get("id_token_hint")
        logout_hint = data.get("logout_hint")
        client_id = data.get("client_id")
        post_logout_redirect_uri = data.get("post_logout_redirect_uri")
        state = data.get("state")
        ui_locales = data.get("ui_locales")

        # When an id_token_hint parameter is present, the OP MUST validate that it
        # was the issuer of the ID Token.
        id_token_claims = None
        if id_token_hint:
            id_token_claims = self._validate_id_token_hint(id_token_hint)
            if not self.validate_id_token_claims(id_token_claims):
                raise InvalidRequestError("Invalid id_token_hint")

        client = None
        if client_id:
            client = self.get_client_by_id(client_id)
        elif id_token_claims:
            client = self.resolve_client_from_id_token_claims(id_token_claims)

        # When both client_id and id_token_hint are present, the OP MUST verify
        # that the Client Identifier matches the one used when issuing the ID Token.
        if client_id and id_token_claims:
            aud = id_token_claims.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud or [])
            if client_id not in aud_list:
                raise InvalidRequestError("'client_id' does not match 'aud' claim")

        redirect_uri = None
        if (
            post_logout_redirect_uri
            and self._validate_post_logout_redirect_uri(
                client, post_logout_redirect_uri
            )
        ) and (
            id_token_claims
            or self.is_post_logout_redirect_uri_legitimate(
                request, post_logout_redirect_uri, client, logout_hint
            )
        ):
            redirect_uri = post_logout_redirect_uri
            if state:
                redirect_uri = add_params_to_uri(redirect_uri, dict(state=state))

        # Logout requests without a valid id_token_hint value are a potential means
        # of denial of service; therefore, OPs should obtain explicit confirmation
        # from the End-User before acting upon them.
        if (
            not id_token_claims
            or self.is_confirmation_needed(request, redirect_uri, client, logout_hint)
        ) and not self.was_confirmation_given():
            return self.create_confirmation_response(
                request, client, redirect_uri, ui_locales
            )

        self.end_session(request, id_token_claims)

        if redirect_uri:
            return 302, "", [("Location", redirect_uri)]
        return self.create_end_session_response(request)

    def _validate_post_logout_redirect_uri(
        self, client, post_logout_redirect_uri: str
    ) -> bool:
        """Check that post_logout_redirect_uri exactly matches a registered URI."""
        if not client:
            return False

        registered_uris = client.client_metadata.get("post_logout_redirect_uris", [])

        return post_logout_redirect_uri in registered_uris

    def get_client_by_id(self, client_id: str):
        """Get a client by its client_id.

        This method must be implemented by developers::

            def get_client_by_id(self, client_id):
                return Client.query.filter_by(client_id=client_id).first()

        :param client_id: The client identifier.
        :return: The client object or None.
        """
        raise NotImplementedError()

    def resolve_client_from_id_token_claims(self, id_token_claims: dict):
        """Resolve the client from ID token claims when client_id is not provided.

        When an id_token_hint is provided without an explicit client_id parameter,
        this method determines which client initiated the logout request based on
        the token claims. The ``aud`` claim may be a single string or an array of
        client identifiers.

        Override this method to implement custom logic for determining the client,
        for example by checking which client the user has an active session with::

            def resolve_client_from_id_token_claims(self, id_token_claims):
                aud = id_token_claims.get("aud")
                if isinstance(aud, str):
                    return self.get_client_by_id(aud)
                # Check which client has an active session
                for client_id in aud:
                    if self.has_active_session_for_client(client_id):
                        return self.get_client_by_id(client_id)
                return None

        By default, returns None requiring the client_id parameter to be provided
        explicitly when the ``aud`` claim is an array.

        :param id_token_claims: The validated ID token claims dictionary.
        :return: The client object or None.
        """
        aud = id_token_claims.get("aud")
        if isinstance(aud, str):
            return self.get_client_by_id(aud)
        return None

    def get_server_jwks(self):
        """Get the JWK set used to validate ID tokens.

        This method must be implemented by developers::

            def get_server_jwks(self):
                return server_jwks().as_dict()

        :return: The JWK set dictionary.
        """
        raise NotImplementedError()

    def validate_id_token_claims(self, id_token_claims: str) -> bool:
        """Validate the ID token claims.

        This method must be implemented by developers. It should verify that
        the token corresponds to an active session in the OP::

            def validate_id_token_claims(self, id_token_claims):
                if id_token_claims["sid"] not in current_sessions(
                    id_token_claims["aud"]
                ):
                    return False
                return True

        :param id_token_claims: The ID token claims dictionary.
        :return: True if the ID token claims dict is valid, False otherwise.
        """
        return True

    def _validate_id_token_hint(self, id_token_hint):
        """When an id_token_hint parameter is present, the OP MUST validate that it was the issuer
        of the ID Token."""
        try:
            claims = jwt.decode(
                id_token_hint,
                self.get_server_jwks(),
                claims_options={"exp": {"validate": lambda c: True}},
            )
            claims.validate()
            return claims
        except JoseError as exc:
            raise InvalidRequestError(exc.description) from exc

    def end_session(self, request: OAuth2Request, id_token_claims: Optional[dict]):
        """Perform the actual session termination.

        This method must be implemented by developers::

            def end_session(self, request, id_token_claims):
                # Terminate session for specific user
                if id_token_claims:
                    user_id = id_token_claims.get("sub")
                    logout_user(user_id)
                logout_current_user()

        :param request: The OAuth2Request object.
        :param id_token_claims: The validated ID token claims, or None.
        """
        raise NotImplementedError()

    def create_end_session_response(self, request: OAuth2Request):
        """Create the response after successful logout when there is no valid redirect uri.

        This method must be implemented by developers::

            def create_end_session_response(self, request):
                return 200, "You have been logged out.", []

        :param request: The OAuth2Request object.
        :return: A tuple of (status_code, body, headers).
        """
        raise NotImplementedError()

    def is_post_logout_redirect_uri_legitimate(
        self,
        request: OAuth2Request,
        post_logout_redirect_uri: Optional[str],
        client,
        logout_hint: Optional[str],
    ) -> bool:
        """Determine if post logout redirection can proceed without a valid id_token_hint.

        An id_token_hint carring an ID Token for the RP is also RECOMMENDED when requesting
        post-logout redirection; if it is not supplied with post_logout_redirect_uri, the OP
        MUST NOT perform post-logout redirection unless the OP has other means of confirming
        the legitimacy of the post-logout redirection target::

            def is_post_logout_redirect_uri_legitimate(
                self, request, post_logout_redirect_uri, client, logout_hint
            ):
                # Allow redirection for trusted clients
                return client and client.is_trusted

        Override this method if you have alternative confirmation mechanisms.

        By default, returns False to disable post logout redirection.

        :param request: The OAuth2Request object.
        :param post_logout_redirect_uri: The post_logout_redirect_uri parameter, or None.
        :param client: The client object, or None.
        :param logout_hint: The logout_hint parameter, or None.
        :return: True if post logout redirection can proceed, False if it cannot.
        """
        return False

    def create_confirmation_response(
        self,
        request: OAuth2Request,
        client,
        redirect_uri: Optional[str],
        ui_locales: Optional[str],
    ):
        """Create a response asking the user to confirm logout.

        This is called when id_token_hint is missing or invalid, or for other specific reasons determined by the OP.

        Override to provide a confirmation UI::

            def create_confirmation_response(
                self, request, client, redirect_uri, ui_locales
            ):
                return (
                    200,
                    render_confirmation_page(
                        client=client,
                        redirect_uri=redirect_uri,
                        state=state,
                        ui_locales=ui_locales,
                    ),
                    [("Content-Type", "text/html")],
                )

        :param request: The OAuth2Request object.
        :param client: The client object, or None.
        :param redirect_uri: The requested redirect URI, or None.
        :param ui_locales: The ui_locales parameter, or None.
        :return: A tuple of (status_code, body, headers).
        """
        return 400, "Logout confirmation required", []

    def was_confirmation_given(self) -> bool:
        """Determine if a confirmation was given for logout.

        The user can use this function to indicate that confirmation has been given
        by the user and they are ready to log out::

            def was_confirmation_given(self):
                return session.get("logout_confirmation", False)

        :return: True if confirmation was given, False otherwise.
        """
        return False

    def is_confirmation_needed(
        self, request, redirect_uri, client, logout_hint
    ) -> bool:
        """Determine if an explicit confirmation by the user is needed for logout.

        Example::

            def is_confirmation_needed(
                self, request, redirect_uri, client, logout_hint
            ):
                user = get_current_user()
                if not user:
                    return False
                return logout_hint and logout_hint != user.user_name

        :param request: The OAuth2Request object.
        :param redirect_uri: The requested redirect URI, or None.
        :param client: The client object, or None.
        :param logout_hint: The logout_hint parameter, or None.
        :return: True if confirmation is needed, False otherwise.
        """
        return False
