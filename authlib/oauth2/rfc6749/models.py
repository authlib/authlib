"""authlib.oauth2.rfc6749.models.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module defines how to construct Client, AuthorizationCode and Token.
"""


class ClientMixin:
    """Implementation of OAuth 2 Client described in :rfc:`6749#section-2` with
    some methods to help validation. A client has at least these information:

    * client_id: A string represents client identifier.
    * client_secret: A string represents client password.
    * token_endpoint_auth_method: A way to authenticate client at token
                                  endpoint.
    """

    def get_client_id(self):
        """A method to return client_id of the client. For instance, the value
        in database is saved in a column called ``client_id``::

            def get_client_id(self):
                return self.client_id

        :return: string
        """
        raise NotImplementedError()

    def get_default_redirect_uri(self):
        """A method to get client default redirect_uri. For instance, the
        database table for client has a column called ``default_redirect_uri``::

            def get_default_redirect_uri(self):
                return self.default_redirect_uri

        :return: A URL string
        """
        raise NotImplementedError()

    def get_allowed_scope(self, scope):
        """A method to return a list of requested scopes which are supported by
        this client. For instance, there is a ``scope`` column::

            def get_allowed_scope(self, scope):
                if not scope:
                    return ""
                allowed = set(scope_to_list(self.scope))
                return list_to_scope([s for s in scope.split() if s in allowed])

        :param scope: the requested scope.
        :return: string of scope
        """
        raise NotImplementedError()

    def check_redirect_uri(self, redirect_uri):
        """Validate redirect_uri parameter in Authorization Endpoints. For
        instance, in the client table, there is an ``allowed_redirect_uris``
        column::

            def check_redirect_uri(self, redirect_uri):
                return redirect_uri in self.allowed_redirect_uris

        :param redirect_uri: A URL string for redirecting.
        :return: bool
        """
        raise NotImplementedError()

    def check_client_secret(self, client_secret):
        """Check client_secret matching with the client. For instance, in
        the client table, the column is called ``client_secret``::

            import secrets

            from authlib.common.encoding import to_bytes


            def check_client_secret(self, client_secret):
                return secrets.compare_digest(
                    to_bytes(self.client_secret), to_bytes(client_secret)
                )

        :param client_secret: A string of client secret
        :return: bool
        """
        raise NotImplementedError()

    def check_endpoint_auth_method(self, method, endpoint):
        """Check if client support the given method for the given endpoint.
        There is a ``token_endpoint_auth_method`` defined via :rfc:`7591`.
        Developers MAY re-implement this method with::

            def check_endpoint_auth_method(self, method, endpoint):
                if endpoint == "token":
                    # if client table has ``token_endpoint_auth_method``
                    return self.token_endpoint_auth_method == method
                return True

        Method values defined by this specification are:

        *  "none": The client is a public client as defined in OAuth 2.0,
            and does not have a client secret.

        *  "client_secret_post": The client uses the HTTP POST parameters
            as defined in OAuth 2.0

        *  "client_secret_basic": The client uses HTTP Basic as defined in
            OAuth 2.0
        """
        raise NotImplementedError()

    def check_response_type(self, response_type):
        """Validate if the client can handle the given response_type. There
        are two response types defined by RFC6749: code and token. Other
        specifications combine several values, such as ``code id_token``.

        Per RFC 6749 §3.1.1, the order of the values does not matter.
        ``normalize_response_type`` sorts them before the comparison. With a
        ``response_types`` column in your client::

            from authlib.oauth2.rfc6749 import normalize_response_type


            def check_response_type(self, response_type):
                return normalize_response_type(response_type) in [
                    normalize_response_type(allowed) for allowed in self.response_types
                ]

        :param response_type: the requested response_type string.
        :return: bool
        """
        raise NotImplementedError()

    def check_grant_type(self, grant_type):
        """Validate if the client can handle the given grant_type. There are
        four grant types defined by RFC6749:

        * authorization_code
        * implicit
        * client_credentials
        * password

        For instance, there is a ``allowed_grant_types`` column in your client::

            def check_grant_type(self, grant_type):
                return grant_type in self.grant_types

        :param grant_type: the requested grant_type string.
        :return: bool
        """
        raise NotImplementedError()


class AuthorizationCodeMixin:
    def get_redirect_uri(self):
        """A method to get authorization code's ``redirect_uri``.
        For instance, the database table for authorization code has a
        column called ``redirect_uri``::

            def get_redirect_uri(self):
                return self.redirect_uri

        :return: A URL string
        """
        raise NotImplementedError()

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::

            def get_scope(self):
                return self.scope

        :return: scope string
        """
        raise NotImplementedError()


class TokenMixin:
    def check_client(self, client):
        """A method to check if this token is issued to the given client.
        For instance, ``client_id`` is saved on token table::

            def check_client(self, client):
                return self.client_id == client.client_id

        :return: bool
        """
        raise NotImplementedError()

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::

            def get_scope(self):
                return self.scope

        :return: scope string
        """
        raise NotImplementedError()

    def get_expires_in(self):
        """A method to get the ``expires_in`` value of the token. e.g.
        the column is called ``expires_in``::

            def get_expires_in(self):
                return self.expires_in

        :return: timestamp int
        """
        raise NotImplementedError()

    def is_expired(self):
        """A method to define if this token is expired. For instance,
        there is a column ``expired_at`` in the table::

            def is_expired(self):
                return self.expired_at < now

        :return: boolean
        """
        raise NotImplementedError()

    def is_revoked(self):
        """A method to define if this token is revoked. For instance,
        there is a boolean column ``revoked`` in the table::

            def is_revoked(self):
                return self.revoked

        :return: boolean
        """
        raise NotImplementedError()

    def get_user(self):
        """A method to get the user object associated with this token:

        .. code-block::

            def get_user(self):
                return User.get(self.user_id)
        """
        raise NotImplementedError()

    def get_client(self) -> ClientMixin:
        """A method to get the client object associated with this token:

        .. code-block::

            def get_client(self):
                return Client.get(self.client_id)
        """
        raise NotImplementedError()


class AuthorizationSessionMixin:
    """The session of a user at the authorization server, during an
    authorization request. Developers MAY implement it, and pass it to
    ``get_consent_grant``. It gives the facts that Authlib needs to decide
    which interactions the user must go through::

        class AuthorizationSession(AuthorizationSessionMixin):
            def __init__(self, user, session):
                self.user = user
                self.session = session

            def get_user(self):
                return self.user

            def get_interaction_time(self, request, interaction):
                if interaction == "login":
                    return self.session.get("auth_time")
                return None


        grant = server.get_consent_grant(session=AuthorizationSession(user, session))

    :class:`~authlib.oauth2.AuthorizationSession` implements it with the session
    of the web framework.
    """

    def get_user(self):
        """Return the user of the session, or ``None`` if they are not logged
        in.
        """
        raise NotImplementedError()

    def get_request_time(self, request):
        """Return the time the authorization request started, as a Unix
        timestamp, or ``None`` if it is unknown. Return the same time for all
        the HTTP requests of one authorization request, for instance before
        and after a login. ``request.authorization_key`` identifies the
        authorization request. Keep the time on the server side, and remove it
        in :meth:`end_request`. Also forget the times older than a few
        minutes: they come from requests that never ended, and a later request
        with the same parameters must not reuse them.

        Authlib calls it on the first use of ``request.request_time``: when
        a rule needs the start time, for instance with ``prompt=login`` or
        ``max_age``, and when the user must go through an interaction. It is
        not called for a silent request, such as with the OpenID Connect
        ``prompt=none``.

        An interaction that the request asks for, such as ``prompt=login`` or
        ``prompt=consent``, is done when it happens after this time. Without
        this time, the user is asked again and again. Times are compared in
        whole seconds, so an interaction in the same second as the start of
        the request is done, even if it happened just before. In tests, set
        the login of the fixtures at least one second earlier.

        :param request: the authorization request
        """
        return None

    def get_interaction_time(self, request, interaction):
        """Return the last time the user went through an interaction, as a
        Unix timestamp, or ``None`` if it never happened or is unknown.

        - ``"login"`` is the time of the last authentication of the user. It
          must come from a real authentication, with a password or another
          factor, and not from a switch to another account or a resumed
          session.
        - ``"consent"`` is the time the user gave the consent that covers the
          request.

        Extensions can ask for other interactions.

        :param request: the authorization request
        :param interaction: the name of the interaction
        """
        return None

    def is_consent_needed(self, request):
        """Tell if the user must give their consent to the request, according
        to the consents stored by the application. For instance, there is no
        consent yet, it was revoked, or it does not cover the requested scope.
        A client can still ask for the consent with ``prompt=consent``.

        :param request: the authorization request, with its ``user``
        """
        return False

    def can_redirect_error(self, request, error):
        """Tell if an error can be sent to the redirect URI of the client.

        Per RFC 9700 §4.11.2, the server should only redirect the user to a
        redirect URI it trusts. Otherwise, the error is returned without
        redirection, and the application can inform the user. For instance,
        return false for the clients that registered themselves.

        :param request: the authorization request, with its ``client``
        :param error: the :class:`~authlib.oauth2.OAuth2Error` to send
        """
        return True

    def end_request(self, request):
        """Called when the authorization request ends: after
        ``create_authorization_response``, and when ``get_consent_grant``
        raises an error. Remove the start time of the request here.
        ``request.authorization_key`` is ``None`` when the error happens
        before the request is identified.

        :param request: the authorization request
        """

    def is_interaction_done(self, request, interaction):
        """Tell if the user went through an interaction after the
        authorization request started.

        :param request: the authorization request, with its ``request_time``
        :param interaction: the name of the interaction
        """
        request_time = request.request_time
        interaction_time = self.get_interaction_time(request, interaction)
        if request_time is None or interaction_time is None:
            return False

        return int(interaction_time) >= int(request_time)
