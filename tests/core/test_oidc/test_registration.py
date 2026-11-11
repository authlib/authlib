import pytest
from joserfc.errors import InvalidClaimError

from authlib.oidc.registration import ClientMetadataClaims


def test_request_uris():
    claims = ClientMetadataClaims(
        {"request_uris": ["https://client.test/request_uris"]}, {}
    )
    claims.validate()

    claims = ClientMetadataClaims({"request_uris": ["invalid"]}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


@pytest.mark.parametrize(
    "uris,metadata,valid",
    [
        (["https://client.test/request"], {}, True),
        (["http://client.test/request"], {"request_object_signing_alg": "RS256"}, True),
        (["http://client.test/request"], {"require_signed_request_object": True}, True),
        (["http://client.test/request"], {}, False),
        (["http://localhost/request"], {}, False),
        (["http://client.test/request"], {"request_object_signing_alg": "none"}, False),
        (["https://client.test/request", "http://client.test/request"], {}, False),
    ],
)
def test_request_uris_https(uris, metadata, valid, monkeypatch):
    """request_uris must use https unless Request Objects are signed."""
    monkeypatch.delenv("AUTHLIB_INSECURE_TRANSPORT", raising=False)
    metadata = {"request_uris": uris, **metadata}
    claims = ClientMetadataClaims(metadata, {})
    if valid:
        claims.validate()
    else:
        with pytest.raises(InvalidClaimError):
            claims.validate()


def test_request_uris_insecure_transport(monkeypatch):
    """AUTHLIB_INSECURE_TRANSPORT allows http request_uris for development."""
    monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "1")
    claims = ClientMetadataClaims({"request_uris": ["http://localhost/request"]}, {})
    claims.validate()


def test_initiate_login_uri():
    claims = ClientMetadataClaims(
        {"initiate_login_uri": "https://client.test/initiate_login_uri"}, {}
    )
    claims.validate()

    claims = ClientMetadataClaims({"initiate_login_uri": "invalid"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_token_endpoint_auth_signing_alg():
    claims = ClientMetadataClaims({"token_endpoint_auth_signing_alg": "RSA256"}, {})
    claims.validate()

    # The value none MUST NOT be used.
    claims = ClientMetadataClaims({"token_endpoint_auth_signing_alg": "none"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_id_token_signed_response_alg():
    claims = ClientMetadataClaims({"id_token_signed_response_alg": "RSA256"}, {})
    claims.validate()


def test_default_max_age():
    claims = ClientMetadataClaims({"default_max_age": 1234}, {})
    claims.validate()

    # The value none MUST NOT be used.
    claims = ClientMetadataClaims({"default_max_age": "invalid"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()
