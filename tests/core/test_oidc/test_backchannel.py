"""Tests for OIDC Back-Channel Logout 1.0."""

import time

import pytest
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import import_key

from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oidc import backchannel
from authlib.oidc import discovery
from authlib.oidc.backchannel import BACKCHANNEL_LOGOUT_EVENT
from authlib.oidc.backchannel import BackchannelLogoutSender
from authlib.oidc.backchannel import ClientMetadataClaims
from authlib.oidc.backchannel import create_logout_token
from tests.util import read_file_path

ISSUER = "https://provider.test"
CLIENT_ID = "client-1"


def get_private_jwks():
    return KeySet.import_key_set(read_file_path("jwks_private.json"))


def decode_token(token):
    jwks = KeySet.import_key_set(read_file_path("jwks_public.json"))
    return jwt.decode(token, jwks)


class FakeClient(ClientMixin):
    def __init__(
        self,
        client_id,
        backchannel_logout_uri=None,
        session_required=False,
        id_token_signed_response_alg=None,
    ):
        self.client_id = client_id
        self.client_metadata = {
            "backchannel_logout_uri": backchannel_logout_uri,
            "backchannel_logout_session_required": session_required,
            "id_token_signed_response_alg": id_token_signed_response_alg,
        }

    def get_client_id(self):
        return self.client_id


class CollectingSender(BackchannelLogoutSender):
    """Test sender that collects delivered tokens instead of sending HTTP."""

    def __init__(self, clients):
        self._clients = clients
        self.delivered = []

    def get_issuer(self):
        return ISSUER

    def resolve_client_private_key(self, client):
        return get_private_jwks()

    def get_logout_sessions(self, sub, sid):
        return [(client, sid) for client in self._clients]

    def deliver_logout_token(self, client, uri, logout_token):
        self.delivered.append((client, uri, logout_token))


def test_create_logout_token_with_sub():
    """A logout token with a sub has the required claims and the logout+jwt type."""
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
    """A logout token can have a sid and no sub."""
    token = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sid="sess-abc")
    claims = decode_token(token).claims

    assert claims["sid"] == "sess-abc"
    assert "sub" not in claims


def test_create_logout_token_with_both():
    """A logout token can have both a sub and a sid."""
    token = create_logout_token(
        ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1", sid="sess-abc"
    )
    claims = decode_token(token).claims

    assert claims["sub"] == "user-1"
    assert claims["sid"] == "sess-abc"


def test_create_logout_token_kid_from_single_key():
    """The header has the kid of a single key."""
    key = get_private_jwks().keys[0]
    token = create_logout_token(issuer=ISSUER, audience=CLIENT_ID, key=key, sub="u")
    assert decode_token(token).header["kid"] == key.kid


def test_create_logout_token_no_kid():
    """The header has no kid when the key has none."""
    key = OctKey.generate_key(256)
    token = create_logout_token(
        issuer=ISSUER, audience=CLIENT_ID, key=key, algorithm="HS256", sub="u"
    )
    assert "kid" not in jwt.decode(token, key, algorithms=["HS256"]).header


def test_create_logout_token_neither_sub_nor_sid_raises():
    """A logout token needs a sub or a sid."""
    with pytest.raises(ValueError, match="sub.*sid|sid.*sub"):
        create_logout_token(ISSUER, CLIENT_ID, get_private_jwks())


def test_create_logout_token_none_algorithm_raises():
    """A logout token cannot use the none algorithm."""
    with pytest.raises(ValueError, match="none"):
        create_logout_token(
            ISSUER, CLIENT_ID, get_private_jwks(), algorithm="none", sub="user-1"
        )


def test_create_logout_token_nonce_not_present():
    """A logout token never has a nonce claim."""
    token = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    assert "nonce" not in decode_token(token).claims


def test_create_logout_token_expiry():
    """The exp claim is iat plus expires_in."""
    before = int(time.time())
    token = create_logout_token(
        ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1", expires_in=60
    )
    after = int(time.time())
    claims = decode_token(token).claims

    assert claims["exp"] - claims["iat"] == 60
    assert before <= claims["iat"] <= after


def test_create_logout_token_accepts_jwks_dict():
    """A JWKS passed as a dict is accepted as the signing key."""
    jwks_dict = read_file_path("jwks_private.json")
    token = create_logout_token(ISSUER, CLIENT_ID, jwks_dict, sub="user-1")
    claims = decode_token(token).claims
    assert claims["iss"] == ISSUER


def test_create_logout_token_accepts_jwk_dict():
    """A single JWK passed as a dict is accepted as the signing key."""
    jwk_dict = read_file_path("jwks_private.json")["keys"][0]
    token = create_logout_token(ISSUER, CLIENT_ID, jwk_dict, sub="user-1")
    claims = jwt.decode(token, import_key(jwk_dict)).claims
    assert claims["iss"] == ISSUER
    assert claims["sub"] == "user-1"


def test_create_logout_token_unique_jti():
    """Each logout token has a different jti."""
    t1 = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    t2 = create_logout_token(ISSUER, CLIENT_ID, get_private_jwks(), sub="user-1")
    assert decode_token(t1).claims["jti"] != decode_token(t2).claims["jti"]


def test_sender_delivers_to_registered_clients():
    """The token is delivered to the client logout URI, with the client as audience."""
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
    """Clients without a backchannel_logout_uri are not notified."""
    client = FakeClient(CLIENT_ID, backchannel_logout_uri=None)
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1")

    assert sender.delivered == []


def test_sender_skips_session_required_client_when_no_sid():
    """Clients that require a sid are not notified when there is no sid."""
    client = FakeClient(
        CLIENT_ID,
        backchannel_logout_uri="https://rp.test/logout",
        session_required=True,
    )
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1", sid=None)

    assert sender.delivered == []


def test_sender_delivers_to_session_required_client_when_sid_provided():
    """Clients that require a sid are notified when there is a sid."""
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
    """Each client with a logout URI gets its own token."""
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


def test_sender_rejects_none_algorithm():
    """The sender does not send logout tokens with the none algorithm."""

    class NoneAlgorithmSender(CollectingSender):
        def get_client_algorithm(self, client):
            return "none"

    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = NoneAlgorithmSender([client])
    with pytest.raises(ValueError, match="none"):
        sender.send_logout(sub="user-1")

    assert sender.delivered == []


def test_sender_uses_client_algorithm():
    """The logout token uses the id_token_signed_response_alg of the client."""
    client = FakeClient(
        CLIENT_ID,
        backchannel_logout_uri="https://rp.test/logout",
        id_token_signed_response_alg="PS256",
    )
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1")

    jwks = KeySet.import_key_set(read_file_path("jwks_public.json"))
    token = jwt.decode(sender.delivered[0][2], jwks, algorithms=["PS256"])
    assert token.header["alg"] == "PS256"


def test_sender_replaces_none_algorithm_with_rs256():
    """A client registered with the none algorithm gets an RS256 logout token."""
    client = FakeClient(
        CLIENT_ID,
        backchannel_logout_uri="https://rp.test/logout",
        id_token_signed_response_alg="none",
    )
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1")

    assert decode_token(sender.delivered[0][2]).header["alg"] == "RS256"


def test_sender_requires_sub_or_sid():
    """send_logout fails without sub and sid, and does not look up the sessions."""

    class FailingSender(CollectingSender):
        def get_logout_sessions(self, sub, sid):
            raise AssertionError("get_logout_sessions must not be called")

    sender = FailingSender([])
    with pytest.raises(ValueError, match="sub"):
        sender.send_logout()


def test_sender_skips_session_without_sub_or_sid():
    """A session without sid is skipped when send_logout has no sub."""

    class SessionsSender(CollectingSender):
        def get_logout_sessions(self, sub, sid):
            return self._clients

    unknown = FakeClient("rp-unknown", backchannel_logout_uri="https://rp1.test/logout")
    known = FakeClient("rp-known", backchannel_logout_uri="https://rp2.test/logout")
    sender = SessionsSender([(unknown, None), (known, "session-1")])
    sender.send_logout(sid="session-1")

    assert [client.client_id for client, _, _ in sender.delivered] == ["rp-known"]


def test_sender_defaults_to_rs256():
    """The logout token uses RS256 when the client has no signing algorithm."""
    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1")

    token = sender.delivered[0][2]
    assert decode_token(token).header["alg"] == "RS256"


def test_sender_uses_client_private_key():
    """The logout token is signed with the key returned for the client."""
    keys = {
        "rp-1": OctKey.generate_key(),
        "rp-2": OctKey.generate_key(),
    }

    class PerClientKeySender(CollectingSender):
        def resolve_client_private_key(self, client):
            return keys[client.client_id]

    clients = [
        FakeClient(
            client_id,
            backchannel_logout_uri="https://rp.test/logout",
            id_token_signed_response_alg="HS256",
        )
        for client_id in keys
    ]
    sender = PerClientKeySender(clients)
    sender.send_logout(sub="user-1")

    for client, _, token in sender.delivered:
        claims = jwt.decode(token, keys[client.client_id], algorithms=["HS256"]).claims
        assert claims["aud"] == client.client_id


def test_sender_uses_client_sub():
    """Each client gets the sub returned by get_client_sub."""

    class PairwiseSender(CollectingSender):
        def get_client_sub(self, client, sub):
            return f"{sub}@{client.client_id}"

    clients = [
        FakeClient("rp-1", backchannel_logout_uri="https://rp1.test/logout"),
        FakeClient("rp-2", backchannel_logout_uri="https://rp2.test/logout"),
    ]
    sender = PairwiseSender(clients)
    sender.send_logout(sub="user-1")

    subs = {decode_token(token).claims["sub"] for _, _, token in sender.delivered}
    assert subs == {"user-1@rp-1", "user-1@rp-2"}


def test_sender_does_not_call_get_client_sub_without_sub():
    """get_client_sub is not called when the logout has no sub."""

    class FailingSubSender(CollectingSender):
        def get_client_sub(self, client, sub):
            raise AssertionError("get_client_sub must not be called")

    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = FailingSubSender([client])
    sender.send_logout(sid="sess-abc")

    assert "sub" not in decode_token(sender.delivered[0][2]).claims


def test_sender_propagates_delivery_errors():
    """An exception raised by deliver_logout_token reaches the caller."""

    class FailingSender(CollectingSender):
        def deliver_logout_token(self, client, uri, logout_token):
            if client.client_id == "rp-1":
                raise ConnectionError("RP unreachable")
            super().deliver_logout_token(client, uri, logout_token)

    clients = [
        FakeClient("rp-1", backchannel_logout_uri="https://rp1.test/logout"),
        FakeClient("rp-2", backchannel_logout_uri="https://rp2.test/logout"),
    ]
    sender = FailingSender(clients)
    with pytest.raises(ConnectionError, match="RP unreachable"):
        sender.send_logout(sub="user-1")

    assert sender.delivered == []


def test_sender_delivers_tokens_in_one_batch():
    """deliver_logout_tokens receives the tokens of all the clients at once."""

    class BatchSender(CollectingSender):
        def deliver_logout_tokens(self, deliveries):
            self.batches = [deliveries]

    clients = [
        FakeClient("rp-1", backchannel_logout_uri="https://rp1.test/logout"),
        FakeClient("rp-2", backchannel_logout_uri="https://rp2.test/logout"),
        FakeClient("rp-3", backchannel_logout_uri=None),
    ]
    sender = BatchSender(clients)
    sender.send_logout(sub="user-1")

    assert len(sender.batches) == 1
    assert [uri for _, uri, _ in sender.batches[0]] == [
        "https://rp1.test/logout",
        "https://rp2.test/logout",
    ]


def test_sender_uses_expires_in():
    """The logout token expires after EXPIRES_IN seconds."""

    class ShortLivedSender(CollectingSender):
        EXPIRES_IN = 30

    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = ShortLivedSender([client])
    sender.send_logout(sub="user-1")

    claims = decode_token(sender.delivered[0][2]).claims
    assert claims["exp"] - claims["iat"] == 30


def test_sender_notifies_each_session_of_the_user():
    """A logout by sub sends a token for each session, with its sid."""

    class SessionsSender(CollectingSender):
        def get_logout_sessions(self, sub, sid):
            return self._clients

    strict = FakeClient(
        "rp-strict",
        backchannel_logout_uri="https://rp1.test/logout",
        session_required=True,
    )
    lenient = FakeClient("rp-lenient", backchannel_logout_uri="https://rp2.test/logout")
    sender = SessionsSender(
        [(strict, "sess-1"), (strict, "sess-2"), (lenient, "sess-1")]
    )
    sender.send_logout(sub="user-1")

    tokens = [
        (client.client_id, decode_token(token).claims)
        for client, _, token in sender.delivered
    ]
    assert [(client_id, claims["sid"]) for client_id, claims in tokens] == [
        ("rp-strict", "sess-1"),
        ("rp-strict", "sess-2"),
        ("rp-lenient", "sess-1"),
    ]
    assert all(claims["sub"] == "user-1" for _, claims in tokens)


def test_sender_skips_session_required_client_when_session_has_no_sid():
    """A client that requires a sid is skipped when its session has no sid."""

    class SessionsSender(CollectingSender):
        def get_logout_sessions(self, sub, sid):
            return self._clients

    strict = FakeClient(
        "rp-strict",
        backchannel_logout_uri="https://rp1.test/logout",
        session_required=True,
    )
    lenient = FakeClient("rp-lenient", backchannel_logout_uri="https://rp2.test/logout")
    sender = SessionsSender([(strict, None), (lenient, None)])
    sender.send_logout(sub="user-1")

    assert [client.client_id for client, _, _ in sender.delivered] == ["rp-lenient"]
    assert "sid" not in decode_token(sender.delivered[0][2]).claims


def test_sender_passes_sid_to_token():
    """The sub and sid are passed to the logout token."""
    client = FakeClient(CLIENT_ID, backchannel_logout_uri="https://rp.test/logout")
    sender = CollectingSender([client])
    sender.send_logout(sub="user-1", sid="sess-xyz")

    claims = decode_token(sender.delivered[0][2]).claims
    assert claims["sub"] == "user-1"
    assert claims["sid"] == "sess-xyz"


def test_backchannel_logout_uri_valid():
    """An https backchannel_logout_uri is valid."""
    claims = ClientMetadataClaims(
        {"backchannel_logout_uri": "https://rp.test/backchannel_logout"}, {}
    )
    claims.validate()


def test_backchannel_logout_uri_missing_is_valid():
    """backchannel_logout_uri is optional."""
    claims = ClientMetadataClaims({}, {})
    claims.validate()


def test_backchannel_logout_uri_invalid_url():
    """A backchannel_logout_uri that is not a URL is rejected."""
    claims = ClientMetadataClaims({"backchannel_logout_uri": "not-a-url"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_backchannel_logout_uri_with_fragment_rejected():
    """A backchannel_logout_uri with a fragment is rejected."""
    claims = ClientMetadataClaims(
        {"backchannel_logout_uri": "https://rp.test/logout#section"}, {}
    )
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_backchannel_logout_uri_insecure_public_client():
    """An http backchannel_logout_uri is rejected for public clients."""
    claims = ClientMetadataClaims(
        {
            "backchannel_logout_uri": "http://rp.test/logout",
            "token_endpoint_auth_method": "none",
        },
        {},
    )
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_backchannel_logout_uri_insecure_confidential_client():
    """An http backchannel_logout_uri is accepted for confidential clients."""
    claims = ClientMetadataClaims(
        {
            "backchannel_logout_uri": "http://rp.test/logout",
            "token_endpoint_auth_method": "client_secret_basic",
        },
        {},
    )
    claims.validate()


def test_backchannel_logout_uri_localhost_rejected():
    """An http backchannel_logout_uri on localhost is rejected for public clients."""
    claims = ClientMetadataClaims(
        {
            "backchannel_logout_uri": "http://localhost:8080/logout",
            "token_endpoint_auth_method": "none",
        },
        {},
    )
    with pytest.raises(InvalidClaimError):
        claims.validate()


def test_backchannel_logout_uri_insecure_transport_allowed(monkeypatch):
    """AUTHLIB_INSECURE_TRANSPORT allows http for public clients."""
    monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "true")
    claims = ClientMetadataClaims(
        {
            "backchannel_logout_uri": "http://localhost:8080/logout",
            "token_endpoint_auth_method": "none",
        },
        {},
    )
    claims.validate()


def test_backchannel_logout_session_required_valid():
    """A boolean backchannel_logout_session_required is valid."""
    claims = ClientMetadataClaims(
        {
            "backchannel_logout_uri": "https://rp.test/logout",
            "backchannel_logout_session_required": True,
        },
        {},
    )
    claims.validate()


def test_backchannel_logout_session_required_invalid_type():
    """A non-boolean backchannel_logout_session_required is rejected."""
    claims = ClientMetadataClaims({"backchannel_logout_session_required": "yes"}, {})
    with pytest.raises(InvalidClaimError):
        claims.validate()


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
    """The back-channel logout provider metadata is accepted."""
    valid_oidc_metadata["backchannel_logout_supported"] = True
    valid_oidc_metadata["backchannel_logout_session_supported"] = True
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])


def test_discovery_backchannel_fields_optional(valid_oidc_metadata):
    """The back-channel logout provider metadata is optional."""
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])


def test_discovery_backchannel_logout_supported_invalid_type(valid_oidc_metadata):
    """A non-boolean backchannel_logout_supported is rejected."""
    valid_oidc_metadata["backchannel_logout_supported"] = "true"
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])


def test_discovery_backchannel_logout_session_supported_invalid_type(
    valid_oidc_metadata,
):
    """A non-boolean backchannel_logout_session_supported is rejected."""
    valid_oidc_metadata["backchannel_logout_session_supported"] = "true"
    metadata = discovery.OpenIDProviderMetadata(valid_oidc_metadata)
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[backchannel.OpenIDProviderMetadata])
