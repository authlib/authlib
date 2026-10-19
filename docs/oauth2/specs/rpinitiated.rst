.. _specs/rpinitiated:

OpenID Connect RP-Initiated Logout 1.0
======================================

.. meta::
    :description: Python API references on OpenID Connect RP-Initiated Logout 1.0
        EndSessionEndpoint with Authlib implementation.

.. module:: authlib.oidc.rpinitiated

This section contains the generic implementation of `OpenID Connect RP-Initiated
Logout 1.0`_. This specification enables Relying Parties (RPs) to request that
an OpenID Provider (OP) log out the End-User.

.. _OpenID Connect RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

The logout goes through the browser. The OP may ask the user to confirm, and
only redirects back to the RP under some conditions:

.. mermaid::

    sequenceDiagram
        autonumber
        participant User as User's browser<br/>(User Agent)
        participant RP as Relying Party<br/>(Client)
        box rgba(80, 120, 220, 0.12) EndSessionEndpoint
            participant OP as OpenID Provider<br/>(Authorization Server)
        end

        Note over RP: logout_redirect()
        RP-->>User: 302 Found → /logout
        User->>OP: GET /logout (id_token_hint, post_logout_redirect_uri, state)
        opt No valid id_token_hint
            OP-->>User: 200 OK + confirmation page
            User->>OP: POST /logout
        end
        Note over OP: end_session()
        alt Valid post_logout_redirect_uri
            autonumber 5
            OP-->>User: 302 Found → post_logout_redirect_uri?state=…
            User->>RP: GET post_logout_redirect_uri?state=…
            Note over RP: validate_logout_response()
        else Otherwise
            autonumber 5
            OP-->>User: 200 OK + logged out page
        end

1. The RP redirects the browser to the end session endpoint of the OP. With
   an Authlib client, ``logout_redirect()`` builds this redirection.
2. The request contains the parameters listed in `Request Parameters`_.
   :class:`EndSessionEndpoint` checks the ``id_token_hint`` signature with
   the OP keys.
3. Interactive mode only, when ``needs_confirmation`` is true: there is no
   valid ``id_token_hint``. The application shows a confirmation page.
4. The user confirms the logout.
5. ``end_session`` terminates the user session. Then:

   a. If the `Post-Logout Redirection`_ conditions are met, the OP
      redirects the browser to ``post_logout_redirect_uri``, with the
      ``state``.
   b. Otherwise, ``create_endpoint_response`` returns ``None`` and the
      application renders its own page.
6. Case a only. The browser returns to the RP. With an Authlib client,
   ``validate_logout_response()`` checks the ``state``.

The ``/logout`` path is an example.

End Session Endpoint
--------------------

To add RP-Initiated Logout support, create a subclass of :class:`EndSessionEndpoint`
and implement the required methods::

    from authlib.oidc.rpinitiated import EndSessionEndpoint

    class MyEndSessionEndpoint(EndSessionEndpoint):
        def get_server_jwks(self):
            return load_jwks()

        def end_session(self, end_session_request):
            # Terminate user session
            session.clear()

    server.register_endpoint(MyEndSessionEndpoint)

Then create a logout route. You have two options:

**Non-interactive mode** (simple, no confirmation page)::

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        return (
            server.create_endpoint_response("end_session")
            or render_template('logged_out.html')
        )

**Interactive mode** (with confirmation page)::

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        try:
            req = server.validate_endpoint_request("end_session")
        except OAuth2Error as error:
            return server.handle_error_response(None, error)

        # Show confirmation page on GET when no id_token_hint was provided
        # User confirms by submitting the form (POST)
        if req.needs_confirmation and request.method == 'GET':
            return render_template('confirm_logout.html', client=req.client)

        return (
            server.create_endpoint_response("end_session", req)
            or render_template('logged_out.html')
        )

The ``create_endpoint_response`` method returns ``None`` when there is no
``post_logout_redirect_uri``, allowing you to provide your own response page.

Request Parameters
~~~~~~~~~~~~~~~~~~

The endpoint accepts the following parameters (via GET or POST):

- **id_token_hint** (Recommended): A previously issued ID Token passed as a hint
  about the End-User's authenticated session.
- **logout_hint** (Optional): A hint to the OP about the End-User that is logging out.
- **client_id** (Optional): The OAuth 2.0 Client Identifier. When both ``client_id``
  and ``id_token_hint`` are present, the OP verifies that the Client Identifier
  matches the ``aud`` claim in the ID Token.
- **post_logout_redirect_uri** (Optional): URI to which the End-User's User Agent
  is redirected after logout. Must exactly match a pre-registered value.
- **state** (Optional): Opaque value used by the RP to maintain state between the
  logout request and the callback.
- **ui_locales** (Optional): End-User's preferred languages for the user interface.

Confirmation Flow
~~~~~~~~~~~~~~~~~

Per the specification, logout requests without a valid ``id_token_hint`` are a
potential means of denial of service. The :attr:`EndSessionRequest.needs_confirmation`
property indicates when user confirmation is recommended.

You control the confirmation page rendering - simply check ``needs_confirmation``
and render your own template as shown in the interactive mode example above.

Post-Logout Redirection
~~~~~~~~~~~~~~~~~~~~~~~

Post-logout redirection only happens when:

1. A ``post_logout_redirect_uri`` is provided
2. The client is resolved (via ``id_token_hint`` or ``client_id``)
3. The URI is registered in the client's ``post_logout_redirect_uris``
4. A valid ``id_token_hint`` is provided, or
   :meth:`EndSessionEndpoint.is_post_logout_redirect_uri_legitimate` returns
   ``True``. By default, it returns ``False``: without ``id_token_hint``,
   there is no redirection.

If all conditions are met, ``EndSessionRequest.redirect_uri`` contains the
validated URI (with ``state`` appended if provided).

If conditions are not met, ``create_endpoint_response`` returns ``None`` and
you should provide a default logout page::

    server.create_endpoint_response("end_session", req) or render_template('logged_out.html')

Session Validation
~~~~~~~~~~~~~~~~~~

When an ``id_token_hint`` is provided, the ``id_token_claims`` attribute of
:class:`EndSessionRequest` contains all claims from the ID Token, including
``sid`` (session ID) if present.

Per the specification, you SHOULD verify that the ``sid`` matches the current
session to detect potentially suspect logout requests::

    def end_session(self, end_session_request):
        if end_session_request.id_token_claims:
            sid = end_session_request.id_token_claims.get("sid")
            if sid and sid != get_current_session_id():
                # Treat as suspect - may require additional confirmation
                pass
        session.clear()

Client Registration
-------------------

Relying Parties can register their ``post_logout_redirect_uris`` through
:ref:`RFC7591: OAuth 2.0 Dynamic Client Registration Protocol <specs/rfc7591>`.

To support RP-Initiated Logout client metadata, add the claims class to your
registration and configuration endpoints.
``MyClientRegistrationEndpoint`` is your subclass of
:class:`~authlib.oauth2.rfc7591.ClientRegistrationEndpoint`::

    from authlib.oauth2 import rfc7591
    from authlib.oidc import registration
    from authlib.oidc import rpinitiated

    authorization_server.register_endpoint(
        MyClientRegistrationEndpoint(
            claims_classes=[
                rfc7591.ClientMetadataClaims,
                registration.ClientMetadataClaims,
                rpinitiated.ClientMetadataClaims,
            ]
        )
    )

The ``post_logout_redirect_uris`` parameter is an array of URLs to which the
End-User's User Agent may be redirected after logout. These URLs SHOULD use
the ``https`` scheme.

API Reference
-------------

.. autoclass:: EndSessionEndpoint
    :member-order: bysource
    :members:

.. autoclass:: EndSessionRequest
    :member-order: bysource
    :members:

.. autoclass:: ClientMetadataClaims
    :member-order: bysource
    :members:

.. autoclass:: OpenIDProviderMetadata
    :member-order: bysource
    :members:
