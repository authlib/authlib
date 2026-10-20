"""Back-channel logout notification sender for OIDC Back-Channel Logout 1.0.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

from .logout_token import create_logout_token


class BackchannelLogoutSender:
    """Send back-channel logout notifications to the RPs.

    Create one instance, and keep a reference to it::

        class MyBackchannelLogoutSender(BackchannelLogoutSender):
            def get_issuer(self):
                return "https://auth.example.com"

            def resolve_client_private_key(self, client):
                return load_private_jwks()

            def get_logout_sessions(self, sub, sid):
                return [(s.client, s.sid) for s in db.query_sessions(sub, sid)]

            def deliver_logout_token(self, client, uri, logout_token):
                try:
                    httpx2.post(uri, data={"logout_token": logout_token}, timeout=5)
                except httpx2.HTTPError:
                    logger.exception("Back-channel logout failed for %s", uri)


        backchannel_logout = MyBackchannelLogoutSender()

    Then call it from anywhere a session ends::

        backchannel_logout.send_logout(sub=sub, sid=sid)

    Each client returned by :meth:`get_logout_sessions` must be a
    :class:`~authlib.oauth2.rfc6749.models.ClientMixin` instance. It must also
    have a ``client_metadata`` dict, like the clients of the SQLAlchemy
    integration. This dict may contain:

    - ``backchannel_logout_uri`` — the RP's back-channel logout endpoint
    - ``backchannel_logout_session_required`` — whether the RP requires ``sid``
      (default: ``False``)
    - ``id_token_signed_response_alg`` — the signing algorithm of the logout
      token (default: ``RS256``)
    """

    #: Lifetime of the logout tokens, in seconds.
    EXPIRES_IN = 120

    def send_logout(self, sub: str | None = None, sid: str | None = None) -> None:
        """Notify all relevant RPs that the user session has ended.

        Each session returned by :meth:`get_logout_sessions` gets its own
        logout token.

        :param sub: Identifier of the logged-out user in your application.
            It is passed to :meth:`get_logout_sessions`. Each client gets the
            ``sub`` claim returned by :meth:`get_client_sub`.
        :param sid: Session ID of the terminated session. Without it, all the
            sessions of the user are logged out.
        :raises ValueError: If neither ``sub`` nor ``sid`` is provided.
        """
        # backchannel §2.4: "A Logout Token MUST contain either a sub or a sid
        # Claim, and MAY contain both."
        if sub is None and sid is None:
            raise ValueError("At least one of 'sub' or 'sid' must be provided")

        sessions = self.get_logout_sessions(sub, sid)
        issuer = self.get_issuer()
        deliveries = []

        for client, session_id in sessions:
            metadata = client.client_metadata
            uri = metadata.get("backchannel_logout_uri")
            if not uri:
                continue

            # backchannel §2.2: "backchannel_logout_session_required - OPTIONAL.
            # Boolean value specifying whether the RP requires that a sid
            # (session ID) Claim be included in the Logout Token to identify
            # the RP session with the OP when the backchannel_logout_uri is
            # used. If omitted, the default value is false."
            session_required = metadata.get(
                "backchannel_logout_session_required", False
            )
            if session_required and session_id is None:
                continue

            client_sub = self.get_client_sub(client, sub) if sub is not None else None
            if client_sub is None and session_id is None:
                continue

            token = create_logout_token(
                issuer=issuer,
                audience=client.get_client_id(),
                key=self.resolve_client_private_key(client),
                algorithm=self.get_client_algorithm(client),
                sub=client_sub,
                sid=session_id,
                expires_in=self.EXPIRES_IN,
            )
            deliveries.append((client, uri, token))

        self.deliver_logout_tokens(deliveries)

    def get_issuer(self) -> str:
        """Return the OP's issuer identifier (e.g. ``'https://auth.example.com'``)."""
        raise NotImplementedError()

    def resolve_client_private_key(self, client):
        """Return the private key used to sign the logout token for this client.

        This is the same key as the one used to sign the ID tokens of the client.
        It can be a joserfc ``Key``, a ``KeySet``, a JWK dict or a JWKS dict.
        """
        # backchannel §2.4: "The same keys are used to sign and encrypt Logout
        # Tokens as are used for ID Tokens."
        raise NotImplementedError()

    def get_logout_sessions(self, sub: str | None, sid: str | None) -> list:
        """Return the ``(client, sid)`` pairs to notify for this session/user.

        Each client must be a
        :class:`~authlib.oauth2.rfc6749.models.ClientMixin` instance with a
        ``client_metadata`` dict. Clients without a ``backchannel_logout_uri``
        in their metadata are silently skipped.

        The ``sid`` of each pair goes in the logout token of this client. Use
        ``None`` if you do not know the session ID. Clients that require a
        ``sid`` are then skipped.

        Return only the active sessions for the given identifiers, not all
        the registered clients. A ``sid`` identifies a session at the OP, and several clients
        can share it. If ``sid`` is provided, return all the clients logged in
        with that session. If only ``sub`` is provided, return all the
        sessions of that user, with their ``sid``. A client with several
        sessions appears once per session::

            def get_logout_sessions(self, sub, sid):
                if sid:
                    sessions = db.query(OIDCSession).filter_by(sid=sid).all()
                else:
                    sessions = db.query(OIDCSession).filter_by(sub=sub).all()
                return [(s.client, s.sid) for s in sessions]
        """
        raise NotImplementedError()

    def deliver_logout_token(self, client, uri: str, logout_token: str) -> None:
        """Send the logout token to ``uri`` via HTTP POST.

        The request body must be ``application/x-www-form-urlencoded`` with a
        ``logout_token`` parameter. The RP answers ``200`` or ``204`` on
        success, and ``400`` on error.

        This method should not raise exceptions. With the default
        :meth:`deliver_logout_tokens`, an exception stops the loop, and the
        next clients are not notified. Catch the errors you expect, and log
        them::

            def deliver_logout_token(self, client, uri, logout_token):
                try:
                    resp = httpx2.post(
                        uri, data={"logout_token": logout_token}, timeout=5
                    )
                    resp.raise_for_status()
                except httpx2.HTTPError:
                    logger.exception("Back-channel logout failed for %s", uri)
        """
        raise NotImplementedError()

    def deliver_logout_tokens(self, deliveries: list) -> None:
        """Send all the logout tokens of a logout.

        ``deliveries`` is a list of ``(client, uri, logout_token)`` tuples.
        By default, the tokens are sent one after another with
        :meth:`deliver_logout_token`.

        Override it to send the tokens in parallel, or to push them to a task
        queue::

            def deliver_logout_tokens(self, deliveries):
                for client, uri, logout_token in deliveries:
                    send_logout_token_task.delay(uri, logout_token)
        """
        # backchannel §2.3: "OPs are encouraged to send logout requests to them
        # in parallel."
        for client, uri, logout_token in deliveries:
            self.deliver_logout_token(client, uri, logout_token)

    def get_client_algorithm(self, client) -> str:
        """Return the algorithm used to sign the logout token for this client.

        Defaults to the ``id_token_signed_response_alg`` client metadata.
        Falls back to ``RS256`` when it is missing or ``none``.
        """
        # backchannel §2.6: "Like ID Tokens, selection of the algorithm used is
        # governed by the id_token_signing_alg_values_supported Discovery
        # parameter and the id_token_signed_response_alg Registration parameter
        # when they are used; otherwise, the value SHOULD be the default of
        # RS256. Additionally, an alg with the value none MUST NOT be used for
        # Logout Tokens."
        alg = client.client_metadata.get("id_token_signed_response_alg")
        if not alg or alg == "none":
            return "RS256"
        return alg

    def get_client_sub(self, client, sub: str) -> str:
        """Return the ``sub`` claim of the logout token for this client.

        ``sub`` is the user identifier passed to :meth:`send_logout`. The
        returned value must be the same as the ``sub`` claim of the ID tokens
        of the client. Override this method when the ``sub`` claim is not the
        user identifier, for instance with pairwise subject identifiers::

            def get_client_sub(self, client, sub):
                if client.client_metadata.get("subject_type") == "pairwise":
                    return compute_pairwise_sub(client, sub)
                return sub

        Defaults to ``sub`` unchanged.
        """
        # backchannel §2.4: "sub - OPTIONAL. Subject Identifier, as specified
        # in Section 2 of [OpenID.Core]."
        return sub
