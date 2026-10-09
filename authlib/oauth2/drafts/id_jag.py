"""Identity Assertion JWT Authorization Grant (ID-JAG).

A draft IETF extension (``draft-ietf-oauth-identity-chaining``) that
enables cross-application access using identity assertions issued by an
external enterprise IdP.

Uses the same ``grant_type`` URI as RFC 7523
(``urn:ietf:params:oauth:grant-type:jwt-bearer``); differentiation is by
the ``typ: oauth-id-jag+jwt`` header in the JWT.

This grant is intentionally **not** a subclass of
:class:`~authlib.oauth2.rfc7523.JWTBearerGrant`: the two grants share
only the grant-type URI and a few trivial helpers.  Inheriting would
force ID-JAG to carry several RFC 7523 hooks
(``resolve_issuer_client``, ``resolve_client_public_key``,
``has_granted_permission``) that have no meaning in the ID-JAG
three-party model.
"""

import logging

from joserfc import jwk
from joserfc import jws
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.util import to_bytes

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import json_loads
from authlib.common.security import generate_token

from ..rfc6749 import BaseGrant
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidGrantError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749 import UnauthorizedClientError
from ..rfc6749 import scope_to_list
from ..rfc7523.assertion import sign_jwt_bearer_assertion
from ..rfc7523.jwt_bearer import JWT_BEARER_GRANT_TYPE

log = logging.getLogger(__name__)


class IDJAGGrant(BaseGrant, TokenEndpointMixin):
    """Identity Assertion JWT Authorization Grant (ID-JAG).

    A 3-party JWT bearer grant where an external IdP issues the
    assertion and the ``client_id`` is decoupled from the issuer.  Uses
    the same grant type URI as RFC 7523; differentiation is by the
    ``typ: oauth-id-jag+jwt`` header in the JWT.

    Subclasses **must** implement:

    - :meth:`get_audiences`
    - :meth:`resolve_issuer_key`
    - :meth:`resolve_client_by_id`
    - :meth:`authenticate_user`
    - :meth:`check_jti`
    - :meth:`check_id_jag_permission`
    """

    #: Same grant_type URI as RFC 7523.  Cannot coexist with
    #: :class:`~authlib.oauth2.rfc7523.JWTBearerGrant` on the same server;
    #: register only one of them.
    GRANT_TYPE = JWT_BEARER_GRANT_TYPE

    #: Required JWT ``typ`` header value per the ID-JAG draft.
    REQUIRED_TYP = "oauth-id-jag+jwt"

    #: Essential claims required by the ID-JAG draft.
    CLAIMS_OPTIONS = {
        "iss": {"essential": True},
        "sub": {"essential": True},
        "aud": {"essential": True},
        "exp": {"essential": True},
        "iat": {"essential": True},
        "jti": {"essential": True},
        "client_id": {"essential": True},
    }

    #: Clock-skew allowance, in seconds.
    LEEWAY = 60

    # ------------------------------------------------------------------
    # Static helper for producing assertions (for tests and clients)
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

        :param key: signing key (private key or shared secret)
        :param issuer: ``iss`` claim - identifies the IdP
        :param audience: ``aud`` claim - the resource AS token endpoint
        :param subject: ``sub`` claim - the end user (required)
        :param client_id: ``client_id`` claim - the application
        :param jti: ``jti`` claim (auto-generated when *None*)
        :param issued_at: ``iat`` claim (defaults to now)
        :param expires_at: ``exp`` claim
        :param claims: additional claims dict
        :param kwargs: forwarded to :func:`sign_jwt_bearer_assertion`
            (e.g. ``alg="RS256"``)
        :return: compact-serialised JWT string
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
    # Grant lifecycle
    # ------------------------------------------------------------------

    def validate_token_request(self):
        """Validate an ID-JAG token request.

        Resolves the client from the ``client_id`` claim (not from
        ``iss``) and enforces the ID-JAG policy hook.
        """
        assertion = self.request.form.get("assertion")
        if not assertion:
            raise InvalidRequestError("Missing 'assertion' in request")

        claims = self._process_assertion_claims(assertion)

        # Resolve client from the client_id claim (NOT from iss).
        client_id_claim = claims["client_id"]
        client = self.resolve_client_by_id(client_id_claim)
        if not client:
            raise InvalidClientError(
                description=f"Unknown client: {client_id_claim}"
            )

        # If client authentication is also present, it must match.
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

        # Authenticate user from sub claim (required by ID-JAG).
        user = self.authenticate_user(claims["sub"])
        if not user:
            raise InvalidGrantError(
                description="Invalid 'sub' value in assertion"
            )

        # Application policy check.
        scopes = scope_to_list(self.request.payload.scope) or []
        if not self.check_id_jag_permission(client, user, scopes):
            raise InvalidGrantError(
                description=(
                    "Permission denied: client is not authorized "
                    "for the requested resource"
                )
            )

        self.request.user = user

    def create_token_response(self):
        """Issue an access token (no refresh token per the ID-JAG draft)."""
        token = self.generate_token(
            scope=self.request.payload.scope,
            user=self.request.user,
            include_refresh_token=False,
        )
        log.debug("Issue token %r to %r", token, self.request.client)
        self.save_token(token)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    # ------------------------------------------------------------------
    # JWT processing (internal)
    # ------------------------------------------------------------------

    def _process_assertion_claims(self, assertion):
        """Extract, verify, and return JWT claims from ``assertion``."""
        headers, raw_claims = self._extract_assertion(assertion)
        self._validate_typ_header(headers)

        issuer = raw_claims.get("iss")
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

        self._verify_claims(token.claims)

        jti = token.claims.get("jti")
        if not self.check_jti(token.claims, jti):
            raise InvalidGrantError(
                description="JWT has already been used (jti replay)"
            )

        return token.claims

    def _extract_assertion(self, assertion: str):
        try:
            obj = jws.extract_compact(to_bytes(assertion))
        except (JoseError, ValueError) as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidGrantError(
                description="Invalid JWT assertion"
            ) from e
        try:
            claims = json_loads(obj.payload)
        except ValueError:
            raise InvalidGrantError(description="Invalid JWT payload.") from None
        return obj.headers(), claims

    def _validate_typ_header(self, headers):
        typ = headers.get("typ")
        if typ != self.REQUIRED_TYP:
            raise InvalidGrantError(
                description=(
                    f"Invalid 'typ' header: expected '{self.REQUIRED_TYP}', "
                    f"got '{typ}'"
                )
            ) from None

    def _verify_claims(self, claims: jwt.Claims):
        options = dict(self.CLAIMS_OPTIONS)
        options["aud"] = {"essential": True, "values": self.get_audiences()}

        claims_requests = jwt.JWTClaimsRegistry(leeway=self.LEEWAY, **options)
        try:
            claims_requests.validate(claims)
        except JoseError as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidGrantError(description=e.description) from e

    # ------------------------------------------------------------------
    # Application hooks
    #
    # All hooks below raise NotImplementedError and MUST be overridden by
    # application subclasses.  This follows the established Authlib
    # pattern (see authlib/oauth2/rfc7523/jwt_bearer.py:199 ff.) rather
    # than abc.abstractmethod, because grants compose via mixins and are
    # instantiated by the framework.
    # ------------------------------------------------------------------

    def get_audiences(self) -> list:
        """Return the list of valid ``aud`` values for this AS.

        Typically the token endpoint URL and/or the AS issuer identifier.
        The returned list must be non-empty; ``aud`` validation is
        mandatory for ID-JAG assertions.
        """
        raise NotImplementedError()

    def resolve_issuer_key(self, issuer, headers) -> jwk.Key | jwk.KeySet:
        """Return the IdP's public key(s) for the given ``issuer``.

        :param issuer: ``iss`` claim identifying the IdP
        :param headers: JWT headers (may contain ``kid``)
        """
        raise NotImplementedError()

    def resolve_client_by_id(self, client_id):
        """Return the client model identified by the ``client_id`` claim,
        or *None* if not found."""
        raise NotImplementedError()

    def authenticate_user(self, subject):
        """Return the user identified by the ``sub`` claim, or *None*."""
        raise NotImplementedError()

    def check_jti(self, claims, jti) -> bool:
        """Return *True* if ``jti`` has not been seen before (replay
        protection), *False* otherwise."""
        raise NotImplementedError()

    def check_id_jag_permission(self, client, user, scopes) -> bool:
        """Application policy: return *True* if *client* may act on
        behalf of *user* for *scopes*."""
        raise NotImplementedError()
