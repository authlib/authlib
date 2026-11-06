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


def _has_type(value, expected) -> bool:
    """Tell if the value has the expected type, such as ``str`` or ``[str]``."""
    if isinstance(expected, list):
        return isinstance(value, list) and all(
            _has_type(item, expected[0]) for item in value
        )

    if isinstance(value, bool) and expected is not bool:
        return False

    return isinstance(value, expected)


class BaseClaims(dict):
    registry_cls = BaseClaimsRegistry
    REGISTERED_CLAIMS = []

    #: Expected type of each claim, such as ``str``, ``(int, float)`` or
    #: ``[str]`` for a list of strings. A claim with another type is invalid,
    #: and a ``null`` claim is removed.
    CLAIM_TYPES = {}

    def __init__(
        self,
        claims: Claims,
        header: Header,
        options: dict[str, ClaimsOption] | None = None,
        params: dict[str, Any] = None,
    ):
        super().__init__(claims)
        self._validate_hooks = {}
        self.header = header
        if options:
            self._extract_validate_hooks(options)
        self.options = options or {}
        self.params = params or {}

    def _extract_validate_hooks(self, options: dict[str, ClaimsOption]):
        for key in options:
            validate = options[key].pop("validate", None)
            if validate:
                self._validate_hooks[key] = validate

    def _run_validate_hooks(self):
        for key in self._validate_hooks:
            validate = self._validate_hooks[key]
            if validate and key in self and not validate(self, self[key]):
                raise InvalidClaimError(key)

    def _validate_claim_types(self):
        for key, expected in self.CLAIM_TYPES.items():
            if key not in self:
                continue

            if self[key] is None:
                del self[key]
            elif not _has_type(self[key], expected):
                raise InvalidClaimError(key)

    def get_registered_claims(self):
        rv = {}
        for k in self.REGISTERED_CLAIMS:
            if k in self:
                rv[k] = self[k]
        return rv

    def validate(self, now=None, leeway=0):
        self._validate_claim_types()
        validator = self.registry_cls(**self.options)
        validator.validate(self)
        self._run_validate_hooks()


class JWTClaims(BaseClaims):
    registry_cls = JWTClaimsRegistry
    REGISTERED_CLAIMS = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

    def validate(self, now=None, leeway=0):
        self._validate_claim_types()
        if self.options:
            validator = self.registry_cls(now, leeway, **self.options)
        else:
            validator = self.registry_cls(now, leeway)
        validator.validate(self)
        self._run_validate_hooks()
