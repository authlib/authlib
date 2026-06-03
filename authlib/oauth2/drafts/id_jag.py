"""Identity Assertion JWT Authorization Grant (ID-JAG).

An extension to RFC 7523 that enables cross-application access using
identity assertions issued by an external enterprise IdP.  Uses the same
``grant_type`` URI as RFC 7523
(``urn:ietf:params:oauth:grant-type:jwt-bearer``); differentiation is by
the ``typ: oauth-id-jag+jwt`` header in the JWT.
"""

import logging

from joserfc import jwk
from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token

from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidGrantError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import UnauthorizedClientError
from ..rfc6749 import scope_to_list
from ..rfc7523.assertion import sign_jwt_bearer_assertion
from ..rfc7523.jwt_bearer import JWT_BEARER_GRANT_TYPE
from ..rfc7523.jwt_bearer import JWTBearerGrant

log = logging.getLogger(__name__)


class IDJAGGrant(JWTBearerGrant):
    """Identity Assertion JWT Authorization Grant (ID-JAG).

    A 3-party JWT bearer grant where an external IdP issues the assertion
    and the ``client_id`` is decoupled from the issuer.  Uses the same
    grant type URI as RFC 7523; differentiation is by the
    ``typ: oauth-id-jag+jwt`` header in the JWT.

    Subclasses **must** implement:

    - :meth:`get_audiences`
    - :meth:`resolve_issuer_key`
    - :meth:`resolve_client_by_id`
    - :meth:`authenticate_user`
    - :meth:`check_jti`
    - :meth:`check_id_jag_permission`
    """

    # Same grant_type as RFC 7523
    GRANT_TYPE = JWT_BEARER_GRANT_TYPE

    # Required JWT typ header value per ID-JAG spec
    REQUIRED_TYP = "oauth-id-jag+jwt"

    #: Stricter claims requirements than base JWTBearerGrant.
    #: ID-JAG mandates sub, iat, jti, client_id in addition to iss, aud, exp.
    CLAIMS_OPTIONS = {
        "iss": {"essential": True},
        "sub": {"essential": True},
        "aud": {"essential": True},
        "exp": {"essential": True},
        "iat": {"essential": True},
        "jti": {"essential": True},
        "client_id": {"essential": True},
    }

    # ------------------------------------------------------------------
    # Static helper
    # ------------------------------------------------------------------

    @staticmethod
    def sign(
        key,
        issuer,
        audience,
        subject,
        client_id,
        jti=None,
        issued_at=None,
        expires_at=None,
        claims=None,
        **kwargs,
    ):
        """Create a signed ID-JAG JWT assertion.

        Unlike the base :meth:`JWTBearerGrant.sign`, ``subject`` and
        ``client_id`` are required parameters, and the ``typ`` header is
        always set to ``oauth-id-jag+jwt``.

        :param key: signing key (private key or shared secret)
        :param issuer: ``iss`` claim – identifies the IdP
        :param audience: ``aud`` claim – the resource AS token endpoint
        :param subject: ``sub`` claim – the end user (required)
        :param client_id: ``client_id`` claim – the application
        :param jti: ``jti`` claim – unique token ID (auto-generated if *None*)
        :param issued_at: ``iat`` claim – Unix timestamp (defaults to now)
        :param expires_at: ``exp`` claim – Unix timestamp
        :param claims: additional claims dict
        :param kwargs: forwarded to :func:`sign_jwt_bearer_assertion`
            (e.g. ``alg="RS256"``)
        :return: compact serialised JWT string
        """
        if not subject:
            raise ValueError("'subject' is required for ID-JAG assertions")

        header = kwargs.pop("header", {})
        header["typ"] = "oauth-id-jag+jwt"

        if claims is None:
            claims = {}
        claims["client_id"] = client_id
        if jti is None:
            jti = generate_token(36)
        claims["jti"] = jti

        return sign_jwt_bearer_assertion(
            key, issuer, audience, subject, issued_at, expires_at, claims,
            header=header, **kwargs,
        )

    # ------------------------------------------------------------------
    # Internal validation helpers
    # ------------------------------------------------------------------

    def _validate_typ_header(self, headers):
        """Ensure the JWT ``typ`` header matches :attr:`REQUIRED_TYP`."""
        typ = headers.get("typ")
        if typ != self.REQUIRED_TYP:
            raise InvalidGrantError(
                description=(
                    f"Invalid 'typ' header: expected '{self.REQUIRED_TYP}', "
                    f"got '{typ}'"
                )
            ) from None

    # ------------------------------------------------------------------
    # Overridden grant methods
    # ------------------------------------------------------------------

    def process_assertion_claims(self, assertion):
        """Extract, verify, and return JWT claims from the assertion.

        Unlike the base class, this method:

        1. Validates the ``typ`` header (``oauth-id-jag+jwt``).
        2. Resolves the signing key via :meth:`resolve_issuer_key` (IdP key)
           instead of :meth:`resolve_client_public_key`.
        3. Checks JTI replay via :meth:`check_jti`.
        """
        headers, claims = self.extract_assertion(assertion)
        self._validate_typ_header(headers)

        issuer = claims.get("iss")
        if not issuer:
            raise InvalidGrantError(
                description="Missing required 'iss' claim in assertion"
            )

        key = import_any_key(self.resolve_issuer_key(issuer, headers))

        try:
            token = jwt.decode(assertion, key)
        except JoseError as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidGrantError(description=e.description) from e
        except ValueError as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidGrantError("Invalid JWT assertion") from None

        self.verify_claims(token.claims)

        jti = token.claims.get("jti")
        if not self.check_jti(token.claims, jti):
            raise InvalidGrantError(
                description="JWT has already been used (jti replay)"
            )

        return token.claims

    def validate_token_request(self):
        """Validate an ID-JAG token request.

        Resolves the client from the ``client_id`` claim (not from ``iss``)
        and enforces the ID-JAG policy hook.
        """
        assertion = self.request.form.get("assertion")
        if not assertion:
            raise InvalidRequestError("Missing 'assertion' in request")

        claims = self.process_assertion_claims(assertion)

        # Resolve client from client_id claim (NOT from iss)
        client_id_claim = claims["client_id"]
        client = self.resolve_client_by_id(client_id_claim)
        if not client:
            raise InvalidClientError(
                description=f"Unknown client: {client_id_claim}"
            )

        # If client authentication is present, verify it matches
        if self.request.client and self.request.client.client_id != client_id_claim:
            raise InvalidGrantError(
                description="Authenticated client does not match 'client_id' claim"
            )

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use "
                f"'grant_type={self.GRANT_TYPE}'"
            )

        self.request.client = client
        log.debug("Validate token request of %s", client)
        self.validate_requested_scope()

        # Authenticate user from sub claim (required in ID-JAG)
        user = self.authenticate_user(claims["sub"])
        if not user:
            raise InvalidGrantError(
                description="Invalid 'sub' value in assertion"
            )

        # Policy check with scopes
        scope = self.request.payload.scope
        scopes = scope_to_list(scope) or []
        if not self.check_id_jag_permission(client, user, scopes):
            raise InvalidGrantError(
                description=(
                    "Permission denied: client is not authorized "
                    "for the requested resource"
                )
            )

        self.request.user = user

    # ------------------------------------------------------------------
    # New hooks (must be implemented by application subclass)
    # ------------------------------------------------------------------

    def resolve_issuer_key(self, issuer, headers) -> jwk.Key | jwk.KeySet:
        """Fetch the IdP's public key(s) by issuer identifier.

        :param issuer: ``iss`` claim value identifying the IdP
        :param headers: JWT headers dict (may contain ``kid``)
        :return: Key or KeySet instance
        """
        raise NotImplementedError()

    def resolve_client_by_id(self, client_id):
        """Resolve a client model by the ``client_id`` claim value.

        :param client_id: ``client_id`` claim from the JWT
        :return: ClientMixin instance, or *None* if not found
        """
        raise NotImplementedError()

    def check_jti(self, claims, jti):
        """Check whether the ``jti`` has already been used (replay protection).

        Return *True* if the jti is acceptable (first use), *False* if it is
        a replay.

        :param claims: full JWT claims dict
        :param jti: ``jti`` claim value
        :return: bool
        """
        raise NotImplementedError()

    def check_id_jag_permission(self, client, user, scopes):
        """Application-defined authorization policy.

        Return *True* if *client* is permitted to act on behalf of *user*
        for the given *scopes*.

        :param client: ClientMixin instance
        :param user: User instance
        :param scopes: list of scope strings (may be empty)
        :return: bool
        """
        raise NotImplementedError()

    # ------------------------------------------------------------------
    # Disabled inherited hooks
    # ------------------------------------------------------------------

    def resolve_issuer_client(self, issuer):
        """Not used by ID-JAG.  Use :meth:`resolve_client_by_id` instead."""
        raise NotImplementedError(
            "Use resolve_client_by_id() for ID-JAG grants"
        )

    def resolve_client_public_key(self, client):
        """Not used by ID-JAG.  Use :meth:`resolve_issuer_key` instead."""
        raise NotImplementedError(
            "Use resolve_issuer_key() for ID-JAG grants"
        )

    def has_granted_permission(self, client, user):
        """Not used by ID-JAG.  Use :meth:`check_id_jag_permission` instead."""
        raise NotImplementedError(
            "Use check_id_jag_permission() for ID-JAG grants"
        )

    # ------------------------------------------------------------------
    # Registration constraint
    # ------------------------------------------------------------------

    @classmethod
    def check_token_endpoint(cls, request):
        """ID-JAG uses the same ``grant_type`` as RFC 7523.

        Cannot coexist with :class:`JWTBearerGrant` on the same server.
        Register only one of them.
        """
        return super().check_token_endpoint(request)

