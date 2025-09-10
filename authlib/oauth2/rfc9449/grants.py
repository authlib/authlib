from authlib.oauth2.rfc6749 import InvalidGrantError
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oauth2.rfc9449.validator import DPoPProofValidator


class DPoPGrantExtension:
    def __init__(self, proof_validator: DPoPProofValidator):
        """DPoP extension to Authorization Code Grant and Refresh Token Grant.
        It enables a client to prove the possession of a public/private key pair
        by including a DPoP header in an HTTP request.

        The AuthorizationCodeGrant MUST save the ``dpop_jkt`` attribute from the
        OAuth2Request into database when ``save_authorization_code``.
        """
        self.proof_validator = proof_validator

    def __call__(self, grant):
        grant.register_hook("after_validate_token_request", self.validate_dpop_jkt)

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