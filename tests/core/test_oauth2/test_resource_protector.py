import pytest

from authlib.oauth2.rfc6749.errors import UnsupportedTokenTypeError
from authlib.oauth2.rfc6749.resource_protector import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator


class _StubBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return None


def test_no_validator_behaves_as_before():
    protector = ResourceProtector()
    with pytest.raises(UnsupportedTokenTypeError):
        protector.get_token_validator("bearer")


def test_token_validator_registered_via_constructor():
    validator = _StubBearerTokenValidator(realm="dev")
    protector = ResourceProtector(token_validator=validator)
    assert protector.get_token_validator("bearer") is validator
    assert protector._default_realm == "dev"
    assert protector._default_auth_type == "bearer"


def test_constructor_and_register_token_validator_are_equivalent():
    via_constructor = ResourceProtector(token_validator=_StubBearerTokenValidator())

    via_register = ResourceProtector()
    via_register.register_token_validator(_StubBearerTokenValidator())

    assert via_constructor._default_auth_type == via_register._default_auth_type
    assert via_constructor._default_realm == via_register._default_realm
    assert list(via_constructor._token_validators) == list(
        via_register._token_validators
    )


def test_additional_validators_can_still_be_registered_after_constructor():
    bearer = _StubBearerTokenValidator()
    protector = ResourceProtector(token_validator=bearer)

    class _MacTokenValidator(BearerTokenValidator):
        TOKEN_TYPE = "mac"

        def authenticate_token(self, token_string):
            return None

    mac = _MacTokenValidator()
    protector.register_token_validator(mac)

    assert protector.get_token_validator("bearer") is bearer
    assert protector.get_token_validator("mac") is mac
    # The constructor-passed validator is still the one that set the default.
    assert protector._default_auth_type == "bearer"
