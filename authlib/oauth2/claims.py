from __future__ import annotations

from typing import Any
from typing import Callable
from typing import TypedDict

from joserfc.errors import InvalidClaimError
from joserfc.jwt import BaseClaimsRegistry
from joserfc.jwt import JWTClaimsRegistry
from joserfc.jwt import Token


class ClaimsOption(TypedDict, total=False):
    essential: bool
    allow_blank: bool | None
    value: str | int | bool
    values: list[str | int | bool] | list[str] | list[int] | list[bool]
    validate: Callable[[BaseClaims, Any], bool]


class BaseClaims(dict):
    registry_cls = BaseClaimsRegistry
    REGISTERED_CLAIMS = []

    def __init__(self, token: Token, options: dict[str, ClaimsOption]):
        super().__init__(token.claims)
        self.token = token
        self.options = options

    @property
    def header(self):
        return self.token.header

    @property
    def claims(self):
        return self.token.claims

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTERED_CLAIMS:
                return self.get(key)
            raise error

    def _run_validate_hooks(self):
        for key in self.options:
            validate = self.options[key].get("validate")
            if validate and key in self.claims and not validate(self, self.claims[key]):
                raise InvalidClaimError(key)

    def validate(self, now=None, leeway=0):
        validator = self.registry_cls(**self.options)
        validator.validate(self.claims)
        self._run_validate_hooks()


class JWTClaims(BaseClaims):
    registry_cls = JWTClaimsRegistry
    REGISTERED_CLAIMS = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

    def validate(self, now=None, leeway=0):
        validator = self.registry_cls(now, leeway, **self.options)
        validator.validate(self.claims)
        self._run_validate_hooks()
