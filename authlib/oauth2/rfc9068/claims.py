from joserfc.errors import InvalidClaimError
from joserfc.jwt import JWTClaimsRegistry

from authlib.oauth2.claims import JWTClaims

_ACCESS_TOKEN_TYPES = ("at+jwt", "application/at+jwt")


def _is_access_token(claims) -> bool:
    """Tell if the JWT header declares an access token."""
    typ = claims.header.get("typ")
    return bool(typ) and typ.lower() in _ACCESS_TOKEN_TYPES


class JWTAccessTokenClaimsValidator(JWTClaimsRegistry):
    def validate_auth_time(self, auth_time):
        if not isinstance(auth_time, (int, float)):
            raise InvalidClaimError("auth_time")
        self.check_value("auth_time", auth_time)

    def validate_amr(self, amr):
        if not isinstance(amr, list):
            raise InvalidClaimError("amr", amr)


class JWTAccessTokenClaims(JWTClaims):
    registry_cls = JWTAccessTokenClaimsValidator
    REGISTERED_CLAIMS = JWTClaims.REGISTERED_CLAIMS + [
        "client_id",
        "auth_time",
        "acr",
        "amr",
        "scope",
        "groups",
        "roles",
        "entitlements",
    ]

    def get_scope(self) -> str | None:
        """Return the value of the ``scope`` claim, or ``None`` if the token
        has no scope.
        """
        return self.get("scope")

    def validate(self, **kwargs):
        # Per RFC 9068 §4, the resource server MUST verify that the typ header
        # value is at+jwt or application/at+jwt.
        if not _is_access_token(self):
            raise InvalidClaimError("typ")

        super().validate(**kwargs)
