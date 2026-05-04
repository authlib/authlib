.. _specs/rfc7523-id-jag:

ID-JAG: Identity Assertion JWT Authorization Grant
==================================================

.. meta::
    :description: API references on ID-JAG (Identity Assertion JWT
        Authorization Grant), a 3-party extension to RFC 7523 for
        cross-application access using identity assertions.

The **Identity Assertion JWT Authorization Grant (ID-JAG)** is an extension
to :ref:`RFC 7523 <specs/rfc7523>` that enables cross-application access
using identity assertions issued by an external enterprise IdP.

.. module:: authlib.oauth2.rfc7523


How ID-JAG Works
----------------

Standard RFC 7523 assumes a **2-party model** where the JWT issuer (``iss``)
is the client itself.  ID-JAG introduces a **3-party model**:

1. An enterprise **IdP** issues a signed JWT (the ID-JAG) to a client
   application via OAuth 2.0 Token Exchange (RFC 8693).
2. The **client** presents that JWT to a Resource Authorization Server using
   the JWT Bearer grant type (``urn:ietf:params:oauth:grant-type:jwt-bearer``)
   to obtain an access token.

The key differences from standard RFC 7523:

* The ``iss`` claim identifies the **IdP**, not the client.
* A separate ``client_id`` claim identifies the **application**.
* The JWT ``typ`` header is ``oauth-id-jag+jwt`` to prevent type confusion.
* ``sub``, ``jti``, and ``iat`` are **required** (optional in base RFC 7523).


Using IDJAGGrant
----------------

``IDJAGGrant`` works the same way as :class:`JWTBearerGrant` — register it
with :meth:`~authlib.oauth2.rfc6749.AuthorizationServer.register_grant`.

You must subclass :class:`IDJAGGrant` and implement all required hooks.


Flask Example
~~~~~~~~~~~~~

::

    from authlib.oauth2.rfc6749 import InvalidGrantError
    from authlib.oauth2.rfc7523 import IDJAGGrant as _IDJAGGrant
    from joserfc.jwk import KeySet

    class IDJAGGrant(_IDJAGGrant):
        def get_audiences(self):
            return ["https://example.com/oauth/token"]

        def resolve_issuer_key(self, issuer, headers):
            """Fetch IdP public keys by issuer URL.

            ``headers`` contains the JWT headers (including ``kid``)
            for key selection within a JWKS.
            """
            idp = TrustedIdP.query.filter_by(issuer=issuer).first()
            if not idp:
                raise InvalidGrantError(description="Untrusted issuer")
            return KeySet.import_key_set(idp.get_jwks())

        def resolve_client_by_id(self, client_id):
            return OAuthClient.query.filter_by(client_id=client_id).first()

        def authenticate_user(self, subject):
            return User.query.filter_by(sub=subject).first()

        def check_jti(self, claims, jti):
            if UsedJTI.query.filter_by(jti=jti).first():
                return False
            UsedJTI.create(jti=jti, exp=claims["exp"])
            return True

        def check_id_jag_permission(self, client, user, scopes):
            return AccessPolicy.is_allowed(client, user, scopes)

    # Register the grant
    authorization_server.register_grant(IDJAGGrant)


Django Example
~~~~~~~~~~~~~~

::

    from authlib.oauth2.rfc6749 import InvalidGrantError
    from authlib.oauth2.rfc7523 import IDJAGGrant as _IDJAGGrant
    from joserfc.jwk import KeySet

    class IDJAGGrant(_IDJAGGrant):
        def get_audiences(self):
            return ["https://example.com/oauth/token"]

        def resolve_issuer_key(self, issuer, headers):
            try:
                idp = TrustedIdP.objects.get(issuer=issuer)
            except TrustedIdP.DoesNotExist:
                raise InvalidGrantError(description="Untrusted issuer")
            return KeySet.import_key_set(idp.jwks)

        def resolve_client_by_id(self, client_id):
            try:
                return OAuthClient.objects.get(client_id=client_id)
            except OAuthClient.DoesNotExist:
                return None

        def authenticate_user(self, subject):
            try:
                return User.objects.get(sub=subject)
            except User.DoesNotExist:
                return None

        def check_jti(self, claims, jti):
            if UsedJTI.objects.filter(jti=jti).exists():
                return False
            UsedJTI.objects.create(jti=jti, exp=claims["exp"])
            return True

        def check_id_jag_permission(self, client, user, scopes):
            return AccessPolicy.objects.filter(
                client=client, user=user
            ).exists()

    # Register the grant
    authorization_server.register_grant(IDJAGGrant)


Creating ID-JAG Assertions
---------------------------

Use :meth:`IDJAGGrant.sign` to create signed ID-JAG JWTs for testing or
client implementations::

    assertion = IDJAGGrant.sign(
        key=private_key,
        issuer="https://idp.example.com",
        audience="https://resource-as.example.com/token",
        subject="user-123",
        client_id="app-456",
        alg="RS256",
    )

Unlike :meth:`JWTBearerGrant.sign`, ``subject`` and ``client_id`` are
**required** parameters.  The ``typ`` header is always set to
``oauth-id-jag+jwt`` and a ``jti`` is auto-generated if not provided.


Required Hooks
--------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Hook
     - Purpose
   * - ``get_audiences()``
     - Return list of valid audience identifiers for this authorization server.
   * - ``resolve_issuer_key(issuer, headers)``
     - Fetch the IdP's public key(s) by issuer identifier.  ``headers``
       contains the JWT headers (including ``kid``) for key selection.
   * - ``resolve_client_by_id(client_id)``
     - Resolve a client model by the ``client_id`` claim.  Return ``None``
       if not found.
   * - ``authenticate_user(subject)``
     - Look up the user by the ``sub`` claim value.
   * - ``check_jti(claims, jti)``
     - Return ``True`` if the ``jti`` is acceptable (first use), ``False``
       if it is a replay.
   * - ``check_id_jag_permission(client, user, scopes)``
     - Return ``True`` if the client may act on behalf of the user for the
       given scopes.


Registration Constraint
-----------------------

``IDJAGGrant`` and ``JWTBearerGrant`` share the same ``grant_type``
(``urn:ietf:params:oauth:grant-type:jwt-bearer``).  Only **one** of them
can be registered on a given ``AuthorizationServer`` at a time.  If both are
registered, only the first one will be matched.


API Reference
-------------

.. autoclass:: IDJAGGrant
    :member-order: bysource
    :members:

