"""Tests for OIDC Back-Channel Logout 1.0."""

import time

import pytest
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oidc import backchannel
from authlib.oidc import discovery
from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from authlib.oidc.backchannel import BackchannelLogoutExtension
from authlib.oidc.backchannel import ClientMetadataClaims
from authlib.oidc.backchannel import create_logout_token
from tests.util import read_file_path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ISSUER = "https://provider.test"
CLIENT_ID = "client-1"


def get_private_jwks():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


def decode_token(token):
    jwks = KeySet.import_key_set(read_file_path("jwks_public.json"))
    return jwt.decode(token, jwks)


class FakeClient:
    def __init__(self, client_id, backchannel_logout_uri=None, session_required=False):
        self.client_id = client_id
        self.client_metadata = {
            "backchannel_logout_uri": backchannel_logout_uri,
            "backchannel_logout_session_required": session_required,
        }


class CollectingSender(BackchannelLogoutExtension):
    """Test sender that collects delivered tokens instead of sending HTTP."""

    def __init__(self, clients):
        self._clients = clients
        self.delivered = []

    def get_issuer(self):
        return ISSUER

    def get_signing_key(self):
        return get_private_jwks()

    def get_logout_clients(self, sub, sid):
        return self._clients

    def deliver_logout_token(self, client, uri, logout_token):
        self.delivered.append((client, uri, logout_token))


# ---------------------------------------------------------------------------
# create_logout_token
# ---------------------------------------------------------------------------


def test_create_logout_token_with_sub():
    token = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    decoded = decode_token(token)
    claims = decoded.claims

    assert claims["iss"] == ISSUER
    assert claims["aud"] == CLIENT_ID
    assert claims["sub"] == "user-1"
    assert "sid" not in claims
    assert BACKCHANNEL_LOGOUT_EVENT in claims["events"]
    assert "jti" in claims
    assert "iat" in claims
    assert "exp" in claims
    assert decoded.header["typ"] == "logout+jwt"


def test_create_logout_token_with_sid():
    token = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sid="sess-abc")
    claims = decode_token(token).claims

    assert claims["sid"] == "sess-abc"
    assert "sub" not in claims


def test_create_logout_token_with_both():
    token = create_logout_token(
        ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1", sid="sess-abc"
    )
    claims = decode_token(token).claims

    assert claims["sub"] == "user-1"
    assert claims["sid"] == "sess-abc"


def test_create_logout_token_neither_sub_nor_sid_raises():
    with pytest.raises(ValueError, match="sub.*sid|sid.*sub"):
        create_logout_token(ISSUER, CLIENT_ID, get_private_jwks())


def test_create_logout_token_nonce_not_present():
    token = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    assert "nonce" not in decode_token(token).claims


def test_create_logout_token_expiry():
    before = int(time.time())
    token = create_logout_token(
        ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1", expires_in=60
    )
    after = int(time.time())
    claims = decode_token(token).claims

    assert claims["exp"] - claims["iat"] == 60
    assert before <= claims["iat"] <= after


def test_create_logout_token_accepts_jwks_dict():
    jwks_dict = read_file_path("jwks_private.json")
    token = create_logout_token(ISSUER, CLIENT_ID, jwks_dict, sub="user-1")
    claims = decode_token(token).claims
    assert claims["iss"] == ISSUER


def test_create_logout_token_unique_jti():
    t1 = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    t2 = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    assert decode_token(t1).claims["jti"] != decode_token(t2).claims["jti"]


# ---------------------------------------------------------------------------
# BackchannelLogoutExtension — extension registration
# ---------------------------------------------------------------------------


class MinimalServer(AuthorizationServer):
    """Minimal server for testing extension registration."""

    def query_client(self, client_id):
        raise NotImplementedError()

    def save_token(self, token, request):
        raise NotImplementedError()

    def send_signal(self, name, *args, **kwargs):
        raise NotImplementedError()

    def create_oauth2_request(self, request):
        raise NotImplementedError()

    def create_json_request(self, request):
        raise NotImplementedError()

    def handle_response(self, status, body, headers):
        raise NotImplementedError()


def test_get_extension_returns_sender():
    server = MinimalServer()
    sender = CollectingSender([])
    server.register_extension(sender)
    assert server.get_extension(BackchannelLogoutExtension) is sender


def test_get_extension_returns_none_when_not_registered():
    server = MinimalServer()
    assert server.get_extension(BackchannelLogoutExtension) is None


def test_get_extension_and_send_logout():
    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = CollectingSender([client])
    server = MinimalServer()
    server.register_extension(sender)

    server.get_extension(BackchannelLogoutExtension).send_logout(sub="user-1")

    assert len(sender.delivered) == 1
    assert decode_token(sender.delivered[0][2]).claims["sub"] == "user-1"


# ---------------------------------------------------------------------------
# BackchannelLogoutExtension — send_logout behaviour
# ---------------------------------------------------------------------------


def test_sender_delivers_to_registered_clients():
    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1")

    assert len(sender.delivered) == 1
    delivered_client, uri, token = sender.delivered[0]
    assert delivered_client is client
    assert uri == "https://rp.test/logout"
    claims = decode_token(token).claims
    assert claims["aud"] == CLIENT_ID
    assert claims["sub"] == "user-1"


def test_sender_skips_clients_without_logout_uri():
    client = FakeClient(CLIENT_ID, backchannel_logout_uri=None)
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1")

    assert sender.delivered == []


def test_sender_skips_session_required_client_when_no_sid():
    client = FakeClient(
        CLIENT_ID,
        backchannel_logout_uri="https://rp.test/logout",
        session_required=True,
    )
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1", sid=None)

    assert sender.delivered == []


def test_sender_delivers_to_session_required_client_when_sid_provided():
    client = FakeClient(
        CLIENT_ID,
        backchannel_logout_uri="https://rp.test/logout",
        session_required=True,
    )
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1", sid="sess-abc")

    assert len(sender.delivered) == 1
    claims = decode_token(sender.delivered[0][2]).claims
    assert claims["sid"] == "sess-abc"


def test_sender_notifies_multiple_clients():
    clients = [
        FakeClient("rp-1", backchannel_logout_uri="https://rp1.test/logout"),
        FakeClient("rp-2", backchannel_logout_uri="https://rp2.test/logout"),
        FakeClient("rp-3", backchannel_logout_uri=None),
    ]
    sender = CollectingSender(clients)
    sender.send_logout(sub="user-1")

    assert len(sender.delivered) == 2
    audiences = {decode_token(token).claims["aud"] for _, _, token in sender.delivered}
    assert audiences == {"rp-1", "rp-2"}


def test_sender_passes_sid_to_token():
    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1", sid="sess-xyz")

    claims = decode_token(sender.delivered[0][2]).claims
    assert claims["sub"] == "user-1"
    assert claims["sid"] == "sess-xyz"


# ---------------------------------------------------------------------------
# ClientMetadataClaims (registration)
# ---------------------------------------------------------------------------


def test_backchannel_logout_uri_valid():
    claims = ClientMetadataClaims(
        {"backchannel_logout_uri": "https://rp.test/backchannel_logout"}, {}
    )
    claims.validate()


def test_backchannel_logout_uri_missing_is_valid():
    claims = ClientMetadataClaims({}, {})
    claims.validate()


def test_backchannel_logout_uri_invalid_url():
    claims = ClientMetadataClaims({"backchannel_logout_uri": "not-a-url"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_backchannel_logout_uri_with_fragment_rejected():
    claims = ClientMetadataClaims(
        {"backchannel_logout_uri": "https://rp.test/logout#section"}, {}
    )
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_backchannel_logout_uri_insecure():
    claims = ClientMetadataClaims(
        {"backchannel_logout_uri": "http://rp.test/logout"}, {}
    )
    with pytest.raises(ValueError, match="https"):
        claims.validate()


def test_backchannel_logout_uri_localhost_allowed():
    claims = ClientMetadataClaims(
        {"backchannel_logout_uri": "http://localhost:8080/logout"}, {}
    )
    claims.validate()


def test_backchannel_logout_session_required_valid():
    claims = ClientMetadataClaims(
        {
            "backchannel_logout_uri": "https://rp.test/logout",
            "backchannel_logout_session_required": True,
        },
        {},
    )
    claims.validate()


def test_backchannel_logout_session_required_invalid_type():
    claims = ClientMetadataClaims({"backchannel_logout_session_required": "yes"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


# ---------------------------------------------------------------------------
# OpenIDProviderMetadata (discovery)
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_oidc_metadata():
    return {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/authorize",
        "token_endpoint": "https://provider.test/token",
        "jwks_uri": "https://provider.test/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def test_discovery_backchannel_logout_supported(valid_oidc_metadata):
    valid_oidc_metadata["backchannel_logout_supported"] = True
    valid_oidc_metadata["backchannel_logout_session_supported"] = True
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])


def test_discovery_backchannel_fields_optional(valid_oidc_metadata):
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])


def test_discovery_backchannel_logout_supported_invalid_type(valid_oidc_metadata):
    valid_oidc_metadata["backchannel_logout_supported"] = "true"
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])


def test_discovery_backchannel_logout_session_supported_invalid_type(
    valid_oidc_metadata,
):
    valid_oidc_metadata["backchannel_logout_session_supported"] = "true"
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])
