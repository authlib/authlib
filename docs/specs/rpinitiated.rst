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

To integrate with Authlib :ref:`flask_oauth2_server` or :ref:`django_oauth2_server`,
developers MUST implement the missing methods of :class:`EndSessionEndpoint`.

.. _OpenID Connect RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

End Session Endpoint
--------------------

The End Session Endpoint handles logout requests from Relying Parties.

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
potential means of denial of service. By default, the endpoint asks for user
confirmation in such cases.

To customize the confirmation page, override :meth:`EndSessionEndpoint.create_confirmation_response`.

After the user confirms logout, you need to indicate that confirmation was given
by overriding :meth:`EndSessionEndpoint.was_confirmation_given`.

If you want to require confirmation even when a valid ``id_token_hint`` is provided
(e.g., when the ``logout_hint`` doesn't match the current user), override
:meth:`EndSessionEndpoint.is_confirmation_needed`.

Post-Logout Redirection Without ID Token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, post-logout redirection requires a valid ``id_token_hint``. If you
have alternative means of confirming the legitimacy of the redirection target,
override :meth:`EndSessionEndpoint.is_post_logout_redirect_uri_legitimate`.

Client Registration
-------------------

Relying Parties can register their ``post_logout_redirect_uris`` through
:ref:`RFC7591: OAuth 2.0 Dynamic Client Registration Protocol <specs/rfc7591>`.

To support RP-Initiated Logout client metadata, add the claims class to your
registration and configuration endpoints::

    from authlib import oidc
    from authlib.oauth2 import rfc7591
    
    authorization_server.register_endpoint(
        ClientRegistrationEndpoint(
            claims_classes=[
                rfc7591.ClientMetadataClaims,
                oidc.registration.ClientMetadataClaims,
                oidc.rpinitiated.ClientMetadataClaims,
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

.. autoclass:: ClientMetadataClaims
    :member-order: bysource
    :members:

.. autoclass:: OpenIDProviderMetadata
    :member-order: bysource
    :members:
