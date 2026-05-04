"""Back-channel logout notification sender for OIDC Back-Channel Logout 1.0.

https://openid.net/specs/openid-connect-backchannel-1_0.html
"""

from .logout_token import create_logout_token


class BackchannelLogoutExtension:
    """Authorization server extension that sends back-channel logout notifications.

    Register it once on the authorization server::

        class MyBackchannelLogoutExtension(BackchannelLogoutExtension):
            def get_issuer(self):
                return "https://auth.example.com"

            def get_signing_key(self):
                return load_private_jwks()

            def get_logout_clients(self, sub, sid):
                return db.query_active_clients(sub=sub, sid=sid)

            def deliver_logout_token(self, client, uri, logout_token):
                requests.post(uri, data={"logout_token": logout_token}, timeout=5)


        server.register_extension(MyBackchannelLogoutExtension())

    Then call it from anywhere a session ends::

        server.get_extension(BackchannelLogoutExtension).send_logout(sub=sub, sid=sid)

    Each client object returned by :meth:`get_logout_clients` is expected to be
    a :class:`~authlib.oauth2.rfc6749.models.ClientMixin` instance. The sender
    accesses ``client.client_id`` and ``client.client_metadata``, which are the
    standard attributes exposed by all authlib client model implementations.

    The ``client_metadata`` dict must contain:

    - ``backchannel_logout_uri`` — the RP's back-channel logout endpoint
    - ``backchannel_logout_session_required`` — whether the RP requires ``sid``
      (default: ``False``)
    """

    def __call__(self, server):
        return self

    def send_logout(self, sub: str | None = None, sid: str | None = None) -> None:
        """Notify all relevant RPs that the user session has ended.

        :param sub: Subject identifier of the logged-out user.
        :param sid: Session ID of the terminated session.
        """
        clients = self.get_logout_clients(sub, sid)
        issuer = self.get_issuer()
        key = self.get_signing_key()
        algorithm = self.get_signing_algorithm()

        for client in clients:
            metadata = client.client_metadata
            uri = metadata.get("backchannel_logout_uri")
            if not uri:
                continue

            # backchannel §2.6: "If the Logout Token contains a sid Claim,
            # its value MUST identify the RP session with the OP that is being
            # logged out. If the RP requires the sid Claim in the Logout Token,
            # it MUST register this requirement by including
            # backchannel_logout_session_required as a registered Client
            # Metadata value set to true."
            session_required = metadata.get(
                "backchannel_logout_session_required", False
            )
            if session_required and sid is None:
                continue

            token = create_logout_token(
                issuer=issuer,
                audience=client.client_id,
                key=key,
                algorithm=algorithm,
                sub=sub,
                sid=sid,
            )
            self.deliver_logout_token(client, uri, token)

    # --- Abstract methods ---

    def get_issuer(self) -> str:
        """Return the OP's issuer identifier (e.g. ``'https://auth.example.com'``)."""
        raise NotImplementedError()

    def get_signing_key(self):
        """Return the private signing key (joserfc ``Key``, ``KeySet``, or JWKS dict)."""
        raise NotImplementedError()

    def get_logout_clients(self, sub: str | None, sid: str | None) -> list:
        """Return the clients to notify for this session/user.

        Each returned object is expected to be a
        :class:`~authlib.oauth2.rfc6749.models.ClientMixin` instance, exposing
        ``client_id`` and ``client_metadata`` attributes. Clients without a
        ``backchannel_logout_uri`` in their metadata are silently skipped.

        Return only clients with an active session for the given identifiers —
        not all registered clients. If ``sid`` is provided, return the single
        client associated with that session. If only ``sub`` is provided, return
        all clients with an active session for that user::

            def get_logout_clients(self, sub, sid):
                if sid:
                    sessions = db.query(OIDCSession).filter_by(sid=sid).all()
                else:
                    sessions = db.query(OIDCSession).filter_by(sub=sub).all()
                return [s.client for s in sessions]
        """
        raise NotImplementedError()

    def deliver_logout_token(self, client, uri: str, logout_token: str) -> None:
        """Send the logout token to ``uri`` via HTTP POST.

        The request body must be ``application/x-www-form-urlencoded`` with a
        single ``logout_token`` parameter. The spec expects ``200`` or ``204``
        on success, ``400`` on error::

            def deliver_logout_token(self, client, uri, logout_token):
                try:
                    resp = requests.post(
                        uri, data={"logout_token": logout_token}, timeout=5
                    )
                    resp.raise_for_status()
                except requests.RequestException as e:
                    logger.warning("Backchannel logout failed for %s: %s", uri, e)
        """
        raise NotImplementedError()

    # --- Overridable ---

    def get_signing_algorithm(self) -> str:
        """Return the JWT signing algorithm. Defaults to ``'RS256'``."""
        return "RS256"
