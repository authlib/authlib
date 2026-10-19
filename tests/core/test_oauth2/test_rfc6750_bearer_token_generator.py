import time
from unittest.mock import patch

from authlib.oauth2.rfc6750.token import BearerTokenGenerator


class FakeClient:
    def get_allowed_scope(self, scope):
        return scope or "read"

    def get_client_id(self):
        return "fake-client"


def _create_generator():
    return BearerTokenGenerator(
        access_token_generator=lambda **kwargs: "fake-access-token",
        refresh_token_generator=lambda **kwargs: "fake-refresh-token",
    )


def test_generate_includes_issued_at_and_expires_at():
    """Token response should include issued_at and expires_at derived from a
    single timestamp so they are always consistent."""
    generator = _create_generator()
    client = FakeClient()

    fixed_time = 12345678
    with patch("authlib.oauth2.rfc6750.token.time") as mock_time:
        mock_time.time.return_value = fixed_time
        token = generator.generate(
            grant_type="client_credentials",
            client=client,
        )

    assert token["issued_at"] == fixed_time
    assert token["expires_at"] == fixed_time + token["expires_in"]


def test_generate_expires_at_uses_custom_expires_in():
    """expires_at should reflect the actual expires_in value used."""
    generator = _create_generator()
    generator.expires_generator = 1234
    client = FakeClient()

    fixed_time = 12345678
    with patch("authlib.oauth2.rfc6750.token.time") as mock_time:
        mock_time.time.return_value = fixed_time
        token = generator.generate(
            grant_type="client_credentials",
            client=client,
        )

    assert token["expires_in"] == 1234
    assert token["issued_at"] == fixed_time
    assert token["expires_at"] == fixed_time + 1234


def test_generate_no_timestamps_when_expires_in_is_zero():
    """When expires_in is 0, neither issued_at nor expires_at should be present."""
    generator = _create_generator()
    generator.expires_generator = 0
    client = FakeClient()

    token = generator.generate(
        grant_type="client_credentials",
        client=client,
        expires_in=0,
    )

    assert "expires_in" not in token
    assert "issued_at" not in token
    assert "expires_at" not in token


def test_generate_token_structure():
    """Token response should have correct structure with all expected fields."""
    generator = _create_generator()
    client = FakeClient()

    token = generator.generate(
        grant_type="client_credentials",
        client=client,
        scope="read write",
        include_refresh_token=True,
    )

    assert token["token_type"] == "Bearer"
    assert token["access_token"] == "fake-access-token"
    assert token["refresh_token"] == "fake-refresh-token"
    assert token["scope"] == "read write"
    assert "expires_in" in token
    assert "issued_at" in token
    assert "expires_at" in token
    assert token["expires_at"] == token["issued_at"] + token["expires_in"]
