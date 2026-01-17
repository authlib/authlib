"""Client metadata for OpenID Connect RP-Initiated Logout 1.0.

https://openid.net/specs/openid-connect-rpinitiated-1_0.html
"""

from authlib.common.security import is_secure_transport
from authlib.common.urls import is_valid_url
from authlib.jose import BaseClaims
from authlib.jose.errors import InvalidClaimError


class ClientMetadataClaims(BaseClaims):
    """Client metadata for OpenID Connect RP-Initiated Logout 1.0.

    This can be used with :ref:`specs/rfc7591` and :ref:`specs/rfc7592` endpoints::

        server.register_endpoint(
            ClientRegistrationEndpoint(
                claims_classes=[
                    rfc7591.ClientMetadataClaims,
                    oidc.registration.ClientMetadataClaims,
                    oidc.rpinitiated.ClientMetadataClaims,
                ]
            )
        )
    """

    REGISTERED_CLAIMS = [
        "post_logout_redirect_uris",
    ]

    def validate(self):
        self._validate_essential_claims()
        self.validate_post_logout_redirect_uris()

    def validate_post_logout_redirect_uris(self):
        """post_logout_redirect_uris is an array of URLs supplied by the RP to which it MAY request that the
        End-User's User Agent be redirected using the post_logout_redirect_uri
        parameter after a logout has been performed.

        These URLs SHOULD use the https scheme and MAY contain port, path, and
        query parameter components; however, they MAY use the http scheme,
        provided that the Client Type is confidential, as defined in
        Section 2.1 of OAuth 2.0, and provided the OP allows the use of
        http RP URIs.
        """
        uris = self.get("post_logout_redirect_uris")
        if uris:
            for uri in uris:
                if not is_valid_url(uri):
                    raise InvalidClaimError("post_logout_redirect_uris")

                # TODO: public client should never be allowed to use http
                if not is_secure_transport(uri):
                    raise ValueError(
                        '"post_logout_redirect_uris" MUST use "https" scheme'
                    )
