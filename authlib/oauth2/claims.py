from __future__ import annotations

from collections.abc import Callable
from typing import Any
from typing import TypedDict

from joserfc.errors import InvalidClaimError
from joserfc.jwt import BaseClaimsRegistry
from joserfc.jwt import Claims
from joserfc.jwt import JWTClaimsRegistry
from joserfc.registry import Header


class ClaimsOption(TypedDict, total=False):
    essential: bool
    allow_blank: bool | None
    value: str | int | bool
    values: list[str | int | bool] | list[str] | list[int] | list[bool]
    validate: Callable[[BaseClaims, Any], bool]


class BaseClaims(dict):
    registry_cls = BaseClaimsRegistry
    REGISTERED_CLAIMS = []

    def __init__(
        self,
        claims: Claims,
        header: Header,
        options: dict[str, ClaimsOption] | None = None,
        params: dict[str, Any] = None,
    ):
        super().__init__(claims)
        self.header = header
        self.claims = claims
        self.options = options or {}
        self.params = params or {}

    def _run_validate_hooks(self):
        if not self.options:
            return
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
        if self.options:
            validator = self.registry_cls(now, leeway, **self.options)
        else:
            validator = self.registry_cls(now, leeway)
        validator.validate(self.claims)
        self._run_validate_hooks()
