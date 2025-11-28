"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""

from authlib.oauth2.rfc6749.errors import ForbiddenError

__all__ = [
    "InvalidDPopProofError",
    "UseDPoPNonceError",
    "InvalidDPoPKeyBindingError",
]


class OAuth2DPoPError(ForbiddenError):
    def __init__(self, description: str = None, for_resource: bool = False):
        self.for_resource = for_resource
        status_code = 401 if for_resource else 400
        super().__init__(description, auth_type="DPoP", status_code=status_code)

    def get_body(self):
        if self.for_resource:
            return []
        return super().get_body()


class InvalidDPopProofError(OAuth2DPoPError):
    error = "invalid_dpop_proof"

    def __init__(self, description: str = None, algs: list[str] = None, for_resource: bool = False):
        self.algs = " ".join(algs)
        super().__init__(description=description, for_resource=for_resource)

    def get_extras(self):
        extras = super().get_extras()
        extras.append(f'algs="{self.algs}"')
        return extras


class UseDPoPNonceError(OAuth2DPoPError):
    error = "use_dpop_nonce"

    def __init__(self, dpop_nonce, description=None, for_resource=False):
        if not description:
            server_type = "Resource" if for_resource else "Authorization"
            description = f"{server_type} server requires nonce in DPoP proof"
        super().__init__(description=description, for_resource=for_resource)
        self.dpop_nonce = dpop_nonce

    def get_headers(self):
        headers = super().get_headers()
        headers.append(("DPoP-Nonce", self.dpop_nonce))
        return headers


class InvalidDPoPKeyBindingError(OAuth2DPoPError):
    error = "invalid_token"
    description = "Invalid DPoP key binding"

    def __init__(self, algs: list[str] = None):
        self.algs = " ".join(algs)
        super().__init__(for_resource=True)

    def get_extras(self):
        extras = super().get_extras()
        extras.append(f'algs="{self.algs}"')
        return extras