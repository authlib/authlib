"""authlib.oauth2.rfc9449.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validate DPoP Token and Proof.
"""
from urllib.parse import urlparse

from authlib.jose import JoseError, JsonWebKey, jwt
from authlib.oauth2.rfc6749 import InvalidGrantError, OAuth2Request, TokenMixin
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from .errors import InvalidDPoPKeyBindingError, InvalidDPopProofError, UseDPoPNonceError
from .nonce import DPoPNonceGenerator


def normalize_url(url):
    """
    The HTTP URI of the request (without query and fragment parts)
    .. _`Section 4.2`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.2
    """
    return urlparse(url)._replace(query="", fragment="").geturl()


class DPoPProofValidator:
    DEFAULT_SUPPORTED_ALGS = ["ES256"]

    def __init__(self, nonce_generator: DPoPNonceGenerator = None, algs: list[str] = None, claims_options: dict = None):
        """Validates that a DPoP Proof is correctly formed for the request.

        :param nonce_generator: generates and manages the current nonces, and checks for a valid nonce when provided
        :param algs: the list of algorithms that this DPoP implementation supports
        :param claims_options: any custom claims validation necessary for this server

        .. _`Section 4.3`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
        """
        self.nonce_generator = nonce_generator
        self.algs = algs or self.DEFAULT_SUPPORTED_ALGS
        self.claims_options = claims_options or {}

    def validate_proof(self, request: OAuth2Request, access_token: str = None, for_resource: bool = False) -> str:
        """
        To validate a DPoP proof, the receiving server MUST ensure the following:
        1. There is not more than one DPoP HTTP request header field.
        2. The DPoP HTTP request header field value is a single and well-formed JWT.
        3. All required claims per Section 4.2 are contained in the JWT.
        4. The typ JOSE Header Parameter has the value dpop+jwt.
        5. The alg JOSE Header Parameter indicates a registered asymmetric
            digital signature algorithm [IANA.JOSE.ALGS], is not none, is
            supported by the application, and is acceptable per local
            policy.
        6. The JWT signature verifies with the public key contained in the
            jwk JOSE Header Parameter.
        7. The jwk JOSE Header Parameter does not contain a private key.
        8. The htm claim matches the HTTP method of the current request.
        9. The htu claim matches the HTTP URI value for the HTTP request in
            which the JWT was received, ignoring any query and fragment
            parts.
        10. If the server provided a nonce value to the client, the nonce
            claim matches the server-provided nonce value.
        11. The creation time of the JWT, as determined by either the iat
            claim or a server managed timestamp via the nonce claim, is
            within an acceptable window (see Section 11.1).
        12. If presented to a protected resource in conjunction with an
            access token,
            *   ensure that the value of the ath claim equals the hash of
                that access token, and
            *   confirm that the public key to which the access token is
                bound matches the public key from the DPoP proof.

        To reduce the likelihood of false negatives, servers SHOULD employ
        syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-
        based normalization (Section 6.2.3 of [RFC3986]) before comparing the
        htu claim.

        These checks may be performed in any order.

        :param request: the current request
        :param access_token: the access token being used to access a protected resource
        :param for_resource: whether or not we're validating for a protected resource or not
        :return: thumbprint of the public key from the DPoP proof
        :raise: InvalidDPopProofError
        :raise: UseDPoPNonceError

        .. _`Section 4.3`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
        """
        if "DPoP" not in request.headers:
            raise InvalidDPopProofError("DPoP proof required", algs=self.algs, for_resource=for_resource)

        proof = request.headers["DPoP"]
        # Validation 1
        if len(proof.split(",")) > 1:
            raise InvalidDPopProofError("DPoP header must contain a single proof", algs=self.algs,
                                        for_resource=for_resource)

        uri = normalize_url(request.uri)

        claims_options = {
            "jti": {"essential": True},
            "iat": {"essential": True},  # Validation 11 # TODO: nonce timestamp?? Not sure what that means
            "htm": {"essential": True, "value": request.method},  # Validation 8
            "htu": {"essential": True, "value": uri},  # Validation 9
        }

        if access_token:
            ath = create_s256_code_challenge(access_token)
            claims_options["ath"] = {"essential": True, "value": ath}  # Validation 12a

        try:
            self.claims_options.update(claims_options)
            # Validation 2, 3, 6
            claims = jwt.decode(proof, None, claims_options=self.claims_options)
            claims.validate(leeway=30)
        except JoseError as error:
            raise InvalidDPopProofError(description=f"DPoP {error.description.lower()}", algs=self.algs,
                                        for_resource=for_resource)

        header = claims.header
        key = JsonWebKey.import_key(header["jwk"])
        self.validate_header(header, for_resource=for_resource)

        # Validation 7
        if not key.public_only:
            raise InvalidDPopProofError("DPoP 'jwk' not a public key",
                                        algs=self.algs,
                                        for_resource=for_resource)

        if self.nonce_generator:
            if "nonce" not in claims:
                raise UseDPoPNonceError(self.nonce_generator.next(), for_resource=for_resource)
            elif not self.nonce_generator.check(claims["nonce"]):
                raise UseDPoPNonceError(self.nonce_generator.next(), description=f"DPoP invalid claim 'nonce'",
                                        for_resource=for_resource)

        return key.thumbprint()

    def validate_header(self, header: dict, for_resource: bool = False):
        """A method to validate if the DPoP proof header contains additional claims. Developers MAY
        re-implement this method.

        :param header: the header extracted from the DPoP proof
        :param for_resource: whether or not we're validating for a protected resource or not
        :raise: InvalidDPopProofError
        """
        # Validation 4
        if "typ" not in header or header["typ"] != "dpop+jwt":
            raise InvalidDPopProofError("DPoP 'typ' header not 'dpop+jwt'",
                                        algs=self.algs,
                                        for_resource=for_resource)

        # Validation 5
        if "alg" not in header or header["alg"] not in self.algs:
            raise InvalidDPopProofError(f"DPoP 'alg' header not in {self.algs}", algs=self.algs,
                                        for_resource=for_resource)


class DPoP:
    def __init__(self, proof_validator: DPoPProofValidator):
        """DPoP extension to Authorization Code Grant and Refresh Token Grant.
        It enables a client to prove the possession of a public/private key pair
        by including a DPoP header in an HTTP request.

        The AuthorizationCodeGrant MUST save the ``dpop_jkt`` attribute from the
        OAuth2Request into database when ``save_authorization_code``.

        Then register this extension via::

            server.register_grant(AuthorizationCodeGrant, [DPoP(proof_validator=dpop_proof_validator)])
            server.register_grant(RefreshTokenGrant, [DPoP(proof_validator=dpop_proof_validator)])
        """
        self.proof_validator = proof_validator

    def __call__(self, grant):
        grant.register_hook(
            "after_validate_token_request",
            self.validate_dpop_jkt,
        )

    def validate_dpop_jkt(self, grant, _):
        request: OAuth2Request = grant.request

        existing_jkt = None
        if hasattr(request, "authorization_code") and request.authorization_code:
            existing_jkt = request.authorization_code.get_dpop_jkt()
        elif hasattr(request, "refresh_token") and request.refresh_token:
            existing_jkt = request.refresh_token.get_dpop_jkt()

        if existing_jkt and "DPoP" not in request.headers:
            raise InvalidGrantError("DPoP proof is required for this request")

        dpop_header_jkt = self.proof_validator.validate_proof(request)

        if existing_jkt != dpop_header_jkt:
            raise InvalidGrantError("DPoP proof does not match the expected JKT")
        request.dpop_jkt = dpop_header_jkt


class DPoPTokenValidator(BearerTokenValidator):
    TOKEN_TYPE = "dpop"

    def __init__(self, proof_validator: DPoPProofValidator):
        super().__init__()
        self.proof_validator = proof_validator

    def validate_token(self, token: TokenMixin, scopes: list[str], request):
        """Validates the DPoP proof against the stored access token"""
        super().validate_token(token, scopes, request)
        access_token = request.headers.get("Authorization").split()[1]
        dpop_header_thumbprint = self.proof_validator.validate_proof(
            request,
            access_token=access_token,
            for_resource=True)
        dpop_token_thumbprint = token.get_dpop_jkt()

        if dpop_header_thumbprint != dpop_token_thumbprint:
            # Validation 12b
            raise InvalidDPoPKeyBindingError(self.proof_validator.algs)
