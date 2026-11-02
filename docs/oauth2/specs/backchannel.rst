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

The logout does not go through the browser. The OP calls each RP directly:

.. mermaid::

    sequenceDiagram
        autonumber
        box rgba(80, 120, 220, 0.12) BackchannelLogoutSender
            participant OP as OpenID Provider<br/>(Authorization Server)
        end
        participant RP as Relying Party<br/>(Client)

        Note over OP: send_logout(sub, sid)
        Note over OP: get_logout_sessions(sub, sid)
        loop Each client with a backchannel_logout_uri
            Note over OP: create_logout_token()
            OP->>RP: POST backchannel_logout_uri (logout_token)
            Note over RP: Validate the logout token<br/>and clear the session
            alt Logout succeeded
                RP-->>OP: 200 OK
            else Invalid token or logout failed
                autonumber 2
                RP-->>OP: 400 Bad Request
            end
        end

The application calls ``send_logout()`` when a session ends at the OP.
``get_logout_sessions()`` returns the sessions of this user, or the clients of
this session. The OP creates a signed logout token for each of them.

1. ``deliver_logout_token()`` sends the token to the ``backchannel_logout_uri``
   of the client, in a form-encoded ``POST`` request. The RP validates the
   token and clears the matching sessions.
2. The RP answers ``200 OK`` on success. Some frameworks answer
   ``204 No Content`` instead. The RP answers ``400 Bad Request`` if the token
   is invalid or the logout failed.

Sending Logout Notifications
-----------------------------

:class:`BackchannelLogoutSender` sends the logout tokens. Subclass it, create
one instance, and keep a reference to it::

    from authlib.oidc.backchannel import BackchannelLogoutSender

    class MyBackchannelLogoutSender(BackchannelLogoutSender):

        def get_issuer(self):
            return "https://auth.example.com"

        def resolve_client_private_key(self, client):
            # Return the key that signs the ID tokens of this client:
            # a joserfc Key, KeySet, JWK dict or JWKS dict.
            return load_private_jwks()

        def get_logout_sessions(self, sub, sid):
            # Return a (client, sid) pair for each active session of this
            # user, or for each client of this session. Each client is a
            # ClientMixin with a client_metadata dict.
            return [(s.client, s.sid) for s in db.query_sessions(sub=sub, sid=sid)]

        def deliver_logout_token(self, client, uri, logout_token):
            # Perform the HTTP POST. Choose your own library and error handling.
            try:
                httpx2.post(uri, data={"logout_token": logout_token}, timeout=5)
            except httpx2.HTTPError:
                logger.exception("Back-channel logout failed for %s", uri)


    backchannel_logout = MyBackchannelLogoutSender()

Then call :meth:`~BackchannelLogoutSender.send_logout` from anywhere a session
ends — an endpoint, an admin view, a background task::

    backchannel_logout.send_logout(sub="user-123", sid="sess-abc")

:meth:`~BackchannelLogoutSender.send_logout` takes care of:

- skipping clients that have no ``backchannel_logout_uri``
- skipping clients that require a ``sid`` when the session has none
- generating a unique, signed logout token per session

Signing Keys and Algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Logout tokens are signed with the same keys as ID tokens.
:meth:`~BackchannelLogoutSender.resolve_client_private_key` returns the key
for each client, like in :class:`~authlib.oidc.core.grants.OpenIDCode`.

The algorithm comes from the ``id_token_signed_response_alg`` client metadata.
It defaults to ``RS256`` when this metadata is missing or ``none``. Override
:meth:`~BackchannelLogoutSender.get_client_algorithm` to change this.

Subject Identifiers
~~~~~~~~~~~~~~~~~~~

The ``sub`` parameter of :meth:`~BackchannelLogoutSender.send_logout` is the
identifier of the user in your application.
:meth:`~BackchannelLogoutSender.get_logout_sessions` receives it to find the
sessions of the user.
:meth:`~BackchannelLogoutSender.get_client_sub` turns it into the ``sub`` claim
of the logout token for each client.

The ``sub`` claim of the logout token must match the ``sub`` claim of the ID
tokens of the client. By default, :meth:`~BackchannelLogoutSender.get_client_sub`
returns ``sub`` unchanged. Override it when the ``sub`` claim of your ID tokens
is not the user identifier. For instance, with pairwise subject identifiers,
this value is different for each client::

    class MyBackchannelLogoutSender(BackchannelLogoutSender):
        def get_client_sub(self, client, sub):
            if client.client_metadata.get("subject_type") == "pairwise":
                return compute_pairwise_sub(client, sub)
            return sub

Integration with RP-Initiated Logout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A common pattern is to trigger backchannel logout from
:class:`~authlib.oidc.rpinitiated.EndSessionEndpoint`::

    from authlib.oidc.rpinitiated import EndSessionEndpoint

    class MyEndSessionEndpoint(EndSessionEndpoint):
        def get_server_jwks(self):
            return load_public_jwks()

        def end_session(self, end_session_request):
            user_id = session.get("user_id")
            sid = session.get("sid")
            session.clear()
            if user_id or sid:
                backchannel_logout.send_logout(sub=user_id, sid=sid)

Use the identifiers of the OP session that you are closing.
Do not use the claims of the ``id_token_hint``.
The ``id_token_hint`` is optional, so the request may have no claims.
With pairwise subject identifiers, its ``sub`` is the value for one client,
not the identifier of the user.

Session Tracking
~~~~~~~~~~~~~~~~

To avoid notifying every registered client on each logout,
:meth:`~BackchannelLogoutSender.get_logout_sessions` should return only the
active sessions for the given user or session ID. Implement it to query
whatever session store your application maintains (e.g. a table of active
``(user, client, sid)`` rows).

It returns ``(client, sid)`` pairs. Each pair gets its own logout token, with
this ``sid``. When you log out a user from all their sessions, return one pair
per session. A client with several sessions then gets one token per session.

If you do not know the ``sid`` of a session, use ``None``. The clients that
set ``backchannel_logout_session_required`` are then skipped, because their
logout token would need a ``sid``. :meth:`~BackchannelLogoutSender.send_logout`
does not report the skipped clients, so these clients are not logged out.

The ``sid`` (session ID) identifies a session at the OP. All the RPs logged in
with this session share the same ``sid``. The RP learns it from the ``sid``
claim of the ID token, and uses it to find its local session when it receives
a logout token.

Authlib does not add the ``sid`` claim to ID tokens. If you advertise
``backchannel_logout_session_supported``, the spec requires the ``sid`` claim
in the ID tokens. With the authorization code flow, you can add it with
:class:`~authlib.oidc.core.grants.OpenIDCode`::

    class MyOpenIDCode(OpenIDCode):
        def get_authorization_code_claims(self, authorization_code):
            claims = super().get_authorization_code_claims(authorization_code)
            claims["sid"] = authorization_code.sid
            return claims

Here, ``authorization_code.sid`` is a column of your authorization code model.
Fill it with the session ID of the user when you create the code.

Call ``send_logout`` with the identifiers that you have.
At least one of ``sub`` and ``sid`` is required.
Without both, ``send_logout`` raises a ``ValueError``::

    # Logout by subject only (all sessions for this user)
    backchannel_logout.send_logout(sub="user-123")

    # Logout a specific session
    backchannel_logout.send_logout(sub="user-123", sid="sess-abc")

    # Session-only logout (when sub is not available)
    backchannel_logout.send_logout(sid="sess-abc")

HTTP Delivery
~~~~~~~~~~~~~

The spec requires a ``POST`` request with ``Content-Type: application/x-www-form-urlencoded``
and a ``logout_token`` parameter. Implement this in
:meth:`~BackchannelLogoutSender.deliver_logout_token`::

    def deliver_logout_token(self, client, uri, logout_token):
        try:
            resp = httpx2.post(uri, data={"logout_token": logout_token}, timeout=5)
            resp.raise_for_status()
        except httpx2.HTTPError:
            logger.exception("Back-channel logout failed for %s", uri)

By default, the tokens are sent one after another. Authlib does not catch the
exceptions raised by
:meth:`~BackchannelLogoutSender.deliver_logout_token`. An exception stops
the loop, and the next clients are not notified. It also reaches the caller of
:meth:`~BackchannelLogoutSender.send_logout`. Catch the errors you expect in
your implementation.

The spec encourages OPs to send the logout requests in parallel. To do so,
override :meth:`~BackchannelLogoutSender.deliver_logout_tokens`. It receives
all the ``(client, uri, logout_token)`` tuples of a logout. For instance, you
can push them to a task queue::

    def deliver_logout_tokens(self, deliveries):
        for client, uri, logout_token in deliveries:
            send_logout_token_task.delay(uri, logout_token)

The tokens are signed before they enter the queue. They expire after
:attr:`~BackchannelLogoutSender.EXPIRES_IN` seconds. Keep the queue delay and
the retries under this limit, or the RPs will reject expired tokens. You can
raise :attr:`~BackchannelLogoutSender.EXPIRES_IN`, but a captured token can
then be replayed for a longer time.

The OP should not send a logout token again, unless the previous request may
have failed because of a temporary error, such as a network outage. In this
case, wait before sending it again.

Logout Token
------------

Logout tokens are generated automatically by :meth:`~BackchannelLogoutSender.send_logout`.
They expire after :attr:`~BackchannelLogoutSender.EXPIRES_IN` seconds, 120 by
default. The spec recommends at most two minutes.

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
registration and configuration endpoints.
``MyClientRegistrationEndpoint`` is your subclass of
:class:`~authlib.oauth2.rfc7591.ClientRegistrationEndpoint`::

    from authlib.oauth2 import rfc7591
    from authlib.oidc import backchannel
    from authlib.oidc import registration

    authorization_server.register_endpoint(
        MyClientRegistrationEndpoint(
            claims_classes=[
                rfc7591.ClientMetadataClaims,
                registration.ClientMetadataClaims,
                backchannel.ClientMetadataClaims,
            ]
        )
    )

The following client metadata parameters are supported:

- **backchannel_logout_uri** — The RP's back-channel logout endpoint. Must not
  contain a fragment. Public clients must use ``https``, even on
  ``localhost``. Confidential clients may use ``http``.
- **backchannel_logout_session_required** — Boolean. When ``True``, the OP will
  only send a logout token to this client if a ``sid`` is available. Defaults to
  ``False``.

.. warning::

    The OP sends ``POST`` requests to the ``backchannel_logout_uri`` of each
    client. With dynamic client registration, anyone can register this URI.
    An attacker can make your OP send requests to your internal network, such
    as ``http://localhost`` or ``http://10.0.0.1``. This is a Server-Side
    Request Forgery (SSRF).

    In :meth:`~BackchannelLogoutSender.deliver_logout_token`, block the
    requests to private, loopback and link-local addresses, after the DNS
    resolution. Do not follow redirections.

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

.. autoclass:: BackchannelLogoutSender
    :member-order: bysource
    :members:

.. autofunction:: create_logout_token

.. autoclass:: ClientMetadataClaims
    :member-order: bysource
    :members:

.. autoclass:: OpenIDProviderMetadata
    :member-order: bysource
    :members:
