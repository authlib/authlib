from authlib.oauth2 import AuthorizationServer
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import AuthorizationCodeGrant
from authlib.oauth2.rfc6749 import BaseGrant
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import RefreshTokenGrant
from authlib.oauth2.rfc9449.grants import DPoPGrantExtension
from authlib.oauth2.rfc9449.registration import ClientMetadataClaims
from authlib.oauth2.rfc9449.validator import DPoPProofValidator


class DPoP:
    def __init__(self, proof_validator: DPoPProofValidator):
        self.proof_validator = proof_validator

    def __call__(self, server: AuthorizationServer):
        server.register_hook("after_get_authorization_grant", self.add_dpop_extension)
        server.register_hook("after_get_token_grant", self.add_dpop_extension_and_confirm_dpop)

    def add_dpop_extension(self, server: AuthorizationServer, grant: BaseGrant):
        if isinstance(grant, AuthorizationCodeGrant) or isinstance(grant, RefreshTokenGrant):
            dpop_grant_extension = DPoPGrantExtension(self.proof_validator)
            dpop_grant_extension(grant)

    def add_dpop_extension_and_confirm_dpop(self, server: AuthorizationServer, grant: BaseGrant):
        client = grant.authenticate_token_endpoint_client()
        client_metadata = self.get_client_metadata(client)
        request: OAuth2Request = grant.request
        if client_metadata and client_metadata.dpop_bound_access_tokens and "DPoP" not in request.headers:
            raise InvalidRequestError(
                "Token requests for this client must use DPoP.",
                state=request.payload.state,
            )

        self.add_dpop_extension(server, grant)

    def get_client_metadata(self, client: ClientMixin) -> ClientMetadataClaims:
        """Return the client metadata.
        When the ``dpop_bound_access_tokens`` claim is :data:`True`,
        the client must use DPoP for token requests.
        If omitted, the default value is false.::
            class DPoP(rfc9449.DPoP):
                def get_client_metadata(self):
                    return ClientMetadataClaims({
                        "dpop_bound_access_tokens": ...,
                    })
        """
        return ClientMetadataClaims()