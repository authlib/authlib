.. _specs/rfc7523-id-jag:

ID-JAG: Identity Assertion JWT Authorization Grant
==================================================

.. meta::
    :description: API references on ID-JAG (Identity Assertion JWT
        Authorization Grant), a 3-party extension to RFC 7523 for
        cross-application access using identity assertions.

The **Identity Assertion JWT Authorization Grant (ID-JAG)** is an extension
to :ref:`RFC 7523 <specs/rfc7523>` that enables cross-application access
using identity assertions issued by the IdP of an organization.
It is defined in :draft:`draft-ietf-oauth-identity-assertion-authz-grant`.

.. module:: authlib.oauth2.drafts


How ID-JAG Works
----------------

A client wants to access an API on behalf of a user:

* The user belongs to an organization, and logs in with the organization IdP.
* The client is registered at the IdP and at the Resource Authorization
  Server of the API.
* The Resource Authorization Server trusts the IdP for the users of this
  organization.

The client does not run an interactive authorization flow at the Resource
Authorization Server. It asks the IdP for an ID-JAG instead. The IdP issues
it if the organization policy allows this client to access this API for this
user. The client then exchanges the ID-JAG for an access token at the
Resource Authorization Server.

The user authorization moves to the IdP, where the organization
administrators control it.

The full flow:

.. mermaid::

    sequenceDiagram
        autonumber
        participant Client
        participant IdP as IdP Authorization Server
        box rgba(80, 120, 220, 0.12) IDJAGGrant
            participant AS as Resource Authorization Server
        end
        participant RS as Resource Server

        Client->>IdP: POST /token (token exchange)
        IdP-->>Client: 200 OK + ID-JAG
        Client->>AS: POST /token (jwt-bearer + client authentication)
        AS-->>Client: 200 OK + access token
        Client->>RS: GET /api (bearer token)
        RS-->>Client: 200 OK + resource

1. The client calls the IdP token endpoint with OAuth 2.0 Token Exchange
   (:rfc:`8693`): ``grant_type=urn:ietf:params:oauth:grant-type:token-exchange``,
   ``requested_token_type=urn:ietf:params:oauth:token-type:id-jag``, and the
   user ID Token as ``subject_token``.
2. The IdP returns the ID-JAG. It is a JWT signed by the IdP, with the
   ``typ: oauth-id-jag+jwt`` header.
3. The client authenticates to the Resource Authorization Server token
   endpoint with its own credentials and sends
   ``grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`` and the ID-JAG
   as ``assertion``. ``IDJAGGrant`` validates client authentication, the
   ``typ`` header, the IdP signature, and the claims. It binds the assertion's
   ``client_id`` to the authenticated client before checking the ``jti``
   and the access policy.
4. The Resource Authorization Server returns an access token, without a
   refresh token.
5. The client calls the API of the Resource Server with the access token, in
   the ``Authorization: Bearer`` header.
6. The Resource Server returns the protected resource.

``IDJAGGrant`` implements steps 3 and 4. The ``/token`` and ``/api`` paths
are examples.

The key differences from :class:`~authlib.oauth2.rfc7523.JWTBearerGrant`:

* The ``iss`` claim identifies the **IdP**, not the client.
* A separate ``client_id`` claim identifies the **client**, by its identifier
  at the Resource Authorization Server. It must match the authenticated client
  redeeming the assertion.
* The ``aud`` claim is the issuer identifier of the Resource Authorization
  Server.
* The JWT ``typ`` header is ``oauth-id-jag+jwt`` to prevent type confusion.
* ``sub``, ``jti``, and ``iat`` are **required**. ``JWTBearerGrant`` does not
  require them.


Using IDJAGGrant
----------------

``IDJAGGrant`` is a standalone grant — it inherits directly from
``BaseGrant`` and ``TokenEndpointMixin``, **not** from
:class:`~authlib.oauth2.rfc7523.JWTBearerGrant`.  The two grants share
only the ``grant_type`` URI; the ID-JAG three-party model has different
hooks (issuer-keyed key resolution, user authorization, and ``jti`` replay
protection) than the RFC 7523 two-party model.

Register it with
:meth:`~authlib.oauth2.rfc6749.AuthorizationServer.register_grant`,
after subclassing it to implement all required hooks::

    from authlib.oauth2.rfc6749 import InvalidGrantError
    from authlib.oauth2.drafts import IDJAGGrant as _IDJAGGrant
    from joserfc.jwk import KeySet

    class IDJAGGrant(_IDJAGGrant):
        def get_audiences(self):
            # The issuer identifier of this authorization server
            return ["https://example.com"]

        def resolve_issuer_key(self, issuer, headers):
            """Fetch IdP public keys by issuer URL.

            ``headers`` contains the JWT headers (including ``kid``)
            for key selection within a JWKS.
            """
            idp = TrustedIdP.query.filter_by(issuer=issuer).first()
            if not idp:
                raise InvalidGrantError(description="Untrusted issuer")
            return KeySet.import_key_set(idp.get_jwks())

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


Client Authentication
~~~~~~~~~~~~~~~~~~~~~

The ID-JAG proves the IdP's authorization; it does not authenticate the client
presenting it. Token requests must authenticate using a method supported by the
grant and configured for the registered client. The default is
``client_secret_basic``. Missing or invalid client credentials return
``invalid_client``. A valid authenticated client whose identifier differs from
the assertion's ``client_id`` claim is rejected with ``invalid_grant``.

Only the authenticated client model is used for grant permissions, application
policy checks, and token issuance. Client lookup is handled by the authorization
server's client authentication, using its configured ``query_client`` or a
registered custom authentication method. The grant does not perform a second
client lookup. Additional application restrictions belong in
``check_id_jag_permission()``. Rejected authentication or a client mismatch does
not record the assertion's ``jti`` as used.

To support another client authentication method, override
``TOKEN_ENDPOINT_AUTH_METHODS`` and configure the client registration to use that
method. For example, to also support ``client_secret_post``::

    from authlib.oauth2.drafts import IDJAGGrant as _IDJAGGrant

    class IDJAGGrant(_IDJAGGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

Custom methods, such as ``private_key_jwt``, must also be registered with the
authorization server. The draft recommends confidential clients; ``none`` is
not enabled by default.

Creating ID-JAG Assertions
---------------------------

Use :meth:`IDJAGGrant.sign` to create signed ID-JAG JWTs for testing or
client implementations::

    assertion = IDJAGGrant.sign(
        key=private_key,
        issuer="https://idp.example.com",
        audience="https://resource-as.example.com",
        subject="user-123",
        client_id="app-456",
        alg="RS256",
    )

Unlike ``JWTBearerGrant.sign()``, ``subject`` and ``client_id`` are
**required** parameters.  The ``typ`` header is always set to
``oauth-id-jag+jwt`` and a ``jti`` is auto-generated if not provided.


Redeeming an ID-JAG
-------------------

Present the assertion along with the client's registered credentials. For a
client using ``client_secret_basic``, an HTTP client can send the request as
follows::

    import requests

    response = requests.post(
        "https://resource-as.example.com/token",
        auth=("app-456", client_secret),
        data={
            "grant_type": IDJAGGrant.GRANT_TYPE,
            "assertion": assertion,
        },
        timeout=10,
    )
    response.raise_for_status()
    token = response.json()

The authenticated client ID (``app-456`` in this example) must match the
``client_id`` claim in the assertion. Sending only the assertion, or adding a
``client_id`` request parameter without credentials, is insufficient.


Required Hooks
--------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Hook
     - Purpose
   * - ``get_audiences()``
     - Return the list of valid ``aud`` values: the issuer identifier of this
       authorization server.
   * - ``resolve_issuer_key(issuer, headers)``
     - Fetch the IdP's public key(s) by issuer identifier.  ``headers``
       contains the JWT headers (including ``kid``) for key selection.
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

