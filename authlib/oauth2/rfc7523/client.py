import logging

from joserfc import jws
from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import json_loads

from ..rfc6749 import InvalidClientError

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
log = logging.getLogger(__name__)


class JWTBearerClientAssertion:
    """Implementation of Using JWTs for Client Authentication, which is
    defined by RFC7523.
    """

    #: Value of ``client_assertion_type`` of JWTs
    CLIENT_ASSERTION_TYPE = ASSERTION_TYPE
    #: Name of the client authentication method
    CLIENT_AUTH_METHOD = "client_assertion_jwt"

    def __init__(self, token_url, validate_jti=True, leeway=60):
        self.token_url = token_url
        self._validate_jti = validate_jti
        # A small allowance of time, typically no more than a few minutes,
        # to account for clock skew. The default is 60 seconds.
        self.leeway = leeway

    def __call__(self, query_client, request):
        data = request.form
        assertion_type = data.get("client_assertion_type")
        assertion = data.get("client_assertion")
        if assertion_type == ASSERTION_TYPE and assertion:
            resolve_key = self.create_resolve_key_func(query_client, request)
            self.process_assertion_claims(assertion, resolve_key)
            return self.authenticate_client(request.client)
        log.debug("Authenticate via %r failed", self.CLIENT_AUTH_METHOD)

    def verify_claims(self, claims: jwt.Claims):
        # iss and sub MUST be the client_id
        options = {
            "iss": {"essential": True},
            "sub": {"essential": True},
            "aud": {"essential": True, "value": self.token_url},
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

    def process_assertion_claims(self, assertion, resolve_key):
        """Extract JWT payload claims from request "assertion", per
        `Section 3.1`_.

        :param assertion: assertion string value in the request
        :param resolve_key: function to resolve the sign key
        :return: JWTClaims
        :raise: InvalidClientError

        .. _`Section 3.1`: https://tools.ietf.org/html/rfc7523#section-3.1
        """
        try:
            token = jwt.decode(assertion, resolve_key)
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

    def create_resolve_key_func(self, query_client, request):
        def resolve_key(obj: jws.CompactSignature):
            # https://tools.ietf.org/html/rfc7523#section-3
            # For client authentication, the subject MUST be the
            # "client_id" of the OAuth client
            try:
                claims = json_loads(obj.payload)
            except ValueError:
                raise InvalidClientError(description="Invalid JWT payload.") from None

            headers = obj.headers()
            client_id = claims["sub"]
            client = query_client(client_id)
            if not client:
                raise InvalidClientError(
                    description="The client does not exist on this server."
                )
            request.client = client
            key = self.resolve_client_public_key(client, headers)
            return import_any_key(key)

        return resolve_key

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

    def resolve_client_public_key(self, client, headers):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            def resolve_client_public_key(self, client, headers):
                return client.public_key
        """
        raise NotImplementedError()
