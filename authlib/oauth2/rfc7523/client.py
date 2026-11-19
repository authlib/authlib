from __future__ import annotations

import logging

from joserfc import jwk
from joserfc import jws
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey
from joserfc.util import to_bytes

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import json_loads
from authlib.deprecate import deprecate

from ..rfc6749 import InvalidClientError

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
log = logging.getLogger(__name__)


class JWTBearerClientAssertion:
    """Implementation of Using JWTs for Client Authentication, which is
    defined by RFC7523.

    Using this class directly, or subclassing it, is deprecated. Use
    :class:`ClientSecretJWTAuthentication` or :class:`PrivateKeyJWTAuthentication`
    instead.
    """

    #: Value of ``client_assertion_type`` of JWTs
    CLIENT_ASSERTION_TYPE = ASSERTION_TYPE
    #: Name of the client authentication method
    CLIENT_AUTH_METHOD = "client_assertion_jwt"
    #: Allowed signing algorithms. ``None`` allows the algorithms that joserfc
    #: recommends.
    ALGORITHMS: list[str] | None = None

    def __init__(self, *, validate_jti=True, leeway=60):
        if not isinstance(
            self, (ClientSecretJWTAuthentication, PrivateKeyJWTAuthentication)
        ):
            deprecate(
                "'JWTBearerClientAssertion' accepts both client_secret_jwt and "
                "private_key_jwt assertions. Use 'ClientSecretJWTAuthentication' "
                "or 'PrivateKeyJWTAuthentication' instead.",
                version="2.0.0",
            )

        self._validate_jti = validate_jti
        # A small allowance of time, typically no more than a few minutes,
        # to account for clock skew. The default is 60 seconds.
        self.leeway = leeway

    def __call__(self, query_client, request):
        data = request.form
        assertion_type = data.get("client_assertion_type")
        assertion = data.get("client_assertion")
        if assertion_type == ASSERTION_TYPE and assertion:
            _, claims = self.extract_assertion(assertion)
            # "sub" is read before the signature and the claims are verified,
            # so it cannot be assumed to be present nor to be a string.
            if "sub" not in claims:
                raise InvalidClientError(description="Missing claim: 'sub'")

            client_id = claims["sub"]
            if not isinstance(client_id, str):
                raise InvalidClientError(description="Invalid claim: 'sub'")

            client = query_client(client_id)
            if not client:
                raise InvalidClientError(
                    description="The client does not exist on this server."
                )

            # Per RFC 7591 §2, token_endpoint_auth_method is the authentication
            # method of the client at the token endpoint.
            if not client.check_endpoint_auth_method(self.CLIENT_AUTH_METHOD, "token"):
                log.debug("Authenticate via %r failed", self.CLIENT_AUTH_METHOD)
                return None

            key = import_any_key(self.resolve_client_public_key(client))

            request.client = client
            self.process_assertion_claims(assertion, key)
            return self.authenticate_client(request.client)
        log.debug("Authenticate via %r failed", self.CLIENT_AUTH_METHOD)

    def verify_claims(self, claims: jwt.Claims):
        audiences = self.get_audiences()
        if not audiences:
            raise InvalidClientError(
                description="No audience identifiers configured for this authorization server."
            )

        # iss and sub MUST be the client_id
        options = {
            "iss": {"essential": True},
            "sub": {"essential": True},
            "aud": {"essential": True, "values": audiences},
            "exp": {"essential": True},
        }
        claims_requests = jwt.JWTClaimsRegistry(leeway=self.leeway, **options)

        try:
            claims_requests.validate(claims)
        except JoseError as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidClientError(description=e.description) from e

        if claims["sub"] != claims["iss"]:
            raise InvalidClientError(description="Issuer and Subject MUST match.")

        if self._validate_jti:
            if "jti" not in claims:
                raise InvalidClientError(description="Missing JWT ID.")

            if not self.validate_jti(claims, claims["jti"]):
                raise InvalidClientError(description="JWT ID is used before.")

    def get_audiences(self):
        """Return a list of valid audience identifiers for this authorization
        server. Per RFC 7523 Section 3, the audience identifies the
        authorization server as an intended audience.

        Developers MUST implement this method to return a non-empty list::

            def get_audiences(self):
                return ["https://example.com/oauth/token", "https://example.com"]

        If this method returns an empty list, the assertion is rejected with
        an ``invalid_client`` error.

        :return: list of valid audience strings
        """
        raise NotImplementedError()  # pragma: no cover

    def process_assertion_claims(self, assertion, resolve_key):
        """Extract JWT payload claims from request "assertion", per
        :rfc:`7523#section-3.1`.

        :param assertion: assertion string value in the request
        :param resolve_key: function to resolve the sign key
        :return: JWTClaims
        :raise: InvalidClientError
        """
        try:
            token = jwt.decode(assertion, resolve_key, algorithms=self.ALGORITHMS)
        except JoseError as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidClientError(description=e.description) from e

        self.verify_claims(token.claims)
        return token.claims

    def authenticate_client(self, client):
        if client.check_endpoint_auth_method(self.CLIENT_AUTH_METHOD, "token"):
            return client
        raise InvalidClientError(
            description=f"The client cannot authenticate with method: {self.CLIENT_AUTH_METHOD}"
        )

    def extract_assertion(self, assertion: str):
        try:
            obj = jws.extract_compact(to_bytes(assertion))
        except JoseError as e:
            log.debug("Assertion Error: %r", e)
            raise InvalidClientError(description="Invalid JWT assertion.") from e

        try:
            claims = json_loads(obj.payload)
        except ValueError:
            raise InvalidClientError(description="Invalid JWT payload.") from None

        if not isinstance(claims, dict):
            raise InvalidClientError(description="Invalid JWT payload.")

        return obj.headers(), claims

    def validate_jti(self, claims, jti):
        """Validate if the given ``jti`` value is used before. Developers
        MUST implement this method::

            def validate_jti(self, claims, jti):
                key = "jti:{}-{}".format(claims["sub"], jti)
                if redis.get(key):
                    return False
                redis.set(key, 1, ex=3600)
                return True
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client) -> jwk.Key | jwk.KeySet:
        """Resolve the client public key for verifying the JWT signature.
        Developers MUST implement this method::

            from joserfc.jwk import KeySet


            def resolve_client_public_key(self, client):
                return KeySet.import_key_set(client.public_jwks)
        """
        raise NotImplementedError()


class ClientSecretJWTAuthentication(JWTBearerClientAssertion):
    """The ``client_secret_jwt`` client authentication method. The client
    signs the JWT with its secret, using an HMAC algorithm.

    Only clients registered with ``client_secret_jwt`` can use it::

        class MyClientSecretJWTAuthentication(ClientSecretJWTAuthentication):
            def get_audiences(self): ...

            def validate_jti(self, claims, jti): ...

            def resolve_client_secret(self, client):
                return client.client_secret


        authorization_server.register_client_auth_method(
            MyClientSecretJWTAuthentication.CLIENT_AUTH_METHOD,
            MyClientSecretJWTAuthentication(),
        )
    """

    CLIENT_AUTH_METHOD = "client_secret_jwt"
    ALGORITHMS = ["HS256", "HS384", "HS512"]

    def resolve_client_secret(self, client) -> str | bytes:
        """Return the secret of the client, in plain text. Developers MUST
        implement this method::

            def resolve_client_secret(self, client):
                return client.client_secret

        The server must be able to read the secret, so it cannot be stored as
        a hash.
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client):
        """Return the secret of the client as an ``OctKey``."""
        try:
            return OctKey.import_key(self.resolve_client_secret(client))
        except (TypeError, ValueError) as error:
            raise InvalidClientError(
                description="The client has no usable secret."
            ) from error


class PrivateKeyJWTAuthentication(JWTBearerClientAssertion):
    """The ``private_key_jwt`` client authentication method. The client signs
    the JWT with its private key, and the server verifies it with the public
    key of the client.

    Only clients registered with ``private_key_jwt`` can use it, and only with
    asymmetric algorithms::

        class MyPrivateKeyJWTAuthentication(PrivateKeyJWTAuthentication):
            def get_audiences(self): ...

            def validate_jti(self, claims, jti): ...

            def resolve_client_public_key(self, client):
                return KeySet.import_key_set(client.jwks)


        authorization_server.register_client_auth_method(
            MyPrivateKeyJWTAuthentication.CLIENT_AUTH_METHOD,
            MyPrivateKeyJWTAuthentication(),
        )
    """

    CLIENT_AUTH_METHOD = "private_key_jwt"
    ALGORITHMS = [
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "Ed25519",
        "Ed448",
        "EdDSA",
    ]
