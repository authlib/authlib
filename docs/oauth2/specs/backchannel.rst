.. _specs/backchannel:

OpenID Connect Back-Channel Logout 1.0
=======================================

.. meta::
    :description: Python API references on OpenID Connect Back-Channel Logout 1.0
        with Authlib implementation.

.. module:: authlib.oidc.backchannel

This section contains the generic implementation of `OpenID Connect Back-Channel
Logout 1.0`_. This specification enables an OpenID Provider (OP) to notify
Relying Parties (RPs) of session termination via direct server-to-server HTTP
requests, without requiring any browser involvement.

.. _OpenID Connect Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html

Overview
--------

When a user's session ends at the OP (for any reason — RP-initiated logout,
admin action, token expiry, etc.), the OP sends a signed **logout token** via
POST to each RP's registered ``backchannel_logout_uri``.

The logout token is a JWT carrying the subject (``sub``) and/or session ID
(``sid``) of the terminated session, allowing each RP to identify and destroy
the corresponding local session.

Sending Logout Notifications
-----------------------------

:class:`BackchannelLogoutExtension` is an authorization server extension. Register
it once, then retrieve it anywhere via
:meth:`~authlib.oauth2.rfc6749.AuthorizationServer.get_extension`::

    from authlib.oidc.backchannel import BackchannelLogoutExtension

    class MyBackchannelLogoutExtension(BackchannelLogoutExtension):

        def get_issuer(self):
            return "https://auth.example.com"

        def get_signing_key(self):
            # Return a joserfc Key, KeySet, or JWKS dict (private key required)
            return load_private_jwks()

        def get_logout_clients(self, sub, sid):
            # Return all clients that have an active session for this user/session.
            # Each object must expose:
            #   - client_id (str)
            #   - client_metadata (dict) with 'backchannel_logout_uri' and
            #     optionally 'backchannel_logout_session_required'
            return db.query_clients_for_session(sub=sub, sid=sid)

        def deliver_logout_token(self, client, uri, logout_token):
            # Perform the HTTP POST. Choose your own library and error handling.
            import requests
            requests.post(uri, data={"logout_token": logout_token}, timeout=5)


    server.register_extension(MyBackchannelLogoutExtension())

Then call :meth:`~BackchannelLogoutExtension.send_logout` from anywhere a session
ends — an endpoint, an admin view, a background task::

    server.get_extension(BackchannelLogoutExtension).send_logout(sub="user-123", sid="sess-abc")

:meth:`~BackchannelLogoutExtension.send_logout` takes care of:

- skipping clients that have no ``backchannel_logout_uri``
- skipping clients that require a ``sid`` when none is available
- generating a unique, signed logout token per client

Integration with RP-Initiated Logout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A common pattern is to trigger backchannel logout from
:class:`~authlib.oidc.rpinitiated.EndSessionEndpoint`::

    from authlib.oidc.backchannel import BackchannelLogoutExtension
    from authlib.oidc.rpinitiated import EndSessionEndpoint

    class MyEndSessionEndpoint(EndSessionEndpoint):

        def end_session(self, end_session_request):
            claims = end_session_request.id_token_claims or {}
            self.server.get_extension(BackchannelLogoutExtension).send_logout(
                sub=claims.get("sub"),
                sid=claims.get("sid"),
            )
            session.clear()

        def get_server_jwks(self):
            return load_public_jwks()

Session Tracking
~~~~~~~~~~~~~~~~

To avoid notifying every registered client on each logout,
:meth:`~BackchannelLogoutExtension.get_logout_clients` should return only the
clients that have an active session for the given user or session ID. Implement
it to query whatever session store your application maintains (e.g. a table of
active ``(user, client)`` pairs keyed by ``sid``).

The ``sid`` (session ID) is established at authentication time and included as a
claim in the ID Token issued to the RP. The RP therefore knows its ``sid`` from
the moment the session is created, and can use it to match an incoming logout
token to the correct local session.

The ``sub`` and ``sid`` parameters are both optional so that ``send_logout`` can
be called with whichever identifiers are available::

    sender = server.get_extension(BackchannelLogoutExtension)

    # Logout by subject only (all sessions for this user)
    sender.send_logout(sub="user-123")

    # Logout a specific session
    sender.send_logout(sub="user-123", sid="sess-abc")

    # Session-only logout (when sub is not available)
    sender.send_logout(sid="sess-abc")

HTTP Delivery
~~~~~~~~~~~~~

The spec requires a ``POST`` request with ``Content-Type: application/x-www-form-urlencoded``
and a single ``logout_token`` parameter. The OP SHOULD attempt parallel delivery
to multiple RPs and MAY retry on failure. Implement this in
:meth:`~BackchannelLogoutExtension.deliver_logout_token`::

    def deliver_logout_token(self, client, uri, logout_token):
        import requests
        try:
            resp = requests.post(
                uri,
                data={"logout_token": logout_token},
                timeout=5,
            )
            resp.raise_for_status()
        except requests.RequestException:
            # Log the failure; decide on retry policy
            logger.warning("Failed to deliver logout to %s", uri)

Logout Token
------------

Logout tokens are generated automatically by :meth:`~BackchannelLogoutExtension.send_logout`.
You can also create them directly with :func:`create_logout_token` if needed::

    from authlib.oidc.backchannel import create_logout_token

    token = create_logout_token(
        issuer="https://auth.example.com",
        audience="client-id",
        key=private_key,
        sub="user-123",
        sid="sess-abc",
        expires_in=120,  # spec recommends at most 120 seconds
    )

The logout token is a JWT with the following claims:

- **iss** — issuer identifier
- **aud** — the client being notified
- **iat** — issued-at timestamp
- **exp** — expiration timestamp
- **jti** — unique token ID (auto-generated, for replay prevention)
- **events** — object containing the ``http://schemas.openid.net/event/backchannel-logout`` member
- **sub** and/or **sid** — at least one is required

The ``nonce`` claim is explicitly forbidden by the specification.

Client Registration
-------------------

Relying Parties register their back-channel logout endpoint via
:ref:`RFC7591: OAuth 2.0 Dynamic Client Registration Protocol <specs/rfc7591>`.

To support back-channel logout client metadata, add the claims class to your
registration and configuration endpoints::

    from authlib import oidc
    from authlib.oauth2 import rfc7591

    authorization_server.register_endpoint(
        ClientRegistrationEndpoint(
            claims_classes=[
                rfc7591.ClientMetadataClaims,
                oidc.registration.ClientMetadataClaims,
                oidc.backchannel.ClientMetadataClaims,
            ]
        )
    )

The following client metadata parameters are supported:

- **backchannel_logout_uri** — The RP's back-channel logout endpoint. Must use
  ``https`` (``http`` is allowed for ``localhost``). Must not contain a fragment.
- **backchannel_logout_session_required** — Boolean. When ``True``, the OP will
  only send a logout token to this client if a ``sid`` is available. Defaults to
  ``False``.

Discovery
---------

To advertise back-channel logout support in your OpenID Provider metadata, add
the discovery class to your metadata validation::

    from authlib.oidc import backchannel
    from authlib.oidc import discovery

    metadata = discovery.OpenIDProviderMetadata({
        ...,
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
    })
    metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])

- **backchannel_logout_supported** — Boolean. Whether the OP supports back-channel
  logout. Defaults to ``False``.
- **backchannel_logout_session_supported** — Boolean. Whether the OP can include a
  ``sid`` claim in logout tokens. Defaults to ``False``.

API Reference
-------------

.. autoclass:: BackchannelLogoutExtension
    :member-order: bysource
    :members:

.. autofunction:: create_logout_token

.. autoclass:: ClientMetadataClaims
    :member-order: bysource
    :members:

.. autoclass:: OpenIDProviderMetadata
    :member-order: bysource
    :members:
