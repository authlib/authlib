import typing as t

from joserfc.errors import InvalidClaimError
from joserfc.jwt import BaseClaimsRegistry


class ClientMetadataValidator(BaseClaimsRegistry):
    @classmethod
    def create_validator(cls, metadata: dict[str, t.Any]):
        return cls()

    @staticmethod
    def set_default_claims(claims: dict[str, t.Any]):
        claims.setdefault("require_signed_request_object", False)

    @property
    def essential_keys(self) -> set[str]:
        return {"require_signed_request_object"}

    def validate_require_signed_request_object(self, value: bool):
        if not isinstance(value, bool):
            raise InvalidClaimError("require_signed_request_object")
