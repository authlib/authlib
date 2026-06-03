"""Tests for IDJAGGrant (Identity Assertion JWT Authorization Grant)."""
import time

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6749 import InvalidClientError
from authlib.oauth2.rfc6749 import InvalidGrantError
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import UnauthorizedClientError
from authlib.oauth2.drafts import IDJAGGrant
from authlib.oauth2.rfc7523 import JWTBearerGrant
from tests.util import read_file_path

_PRIVATE_PEM = read_file_path("rsa_private.pem")
_PUBLIC_PEM = read_file_path("rsa_public.pem")


@pytest.fixture
def rsa_private():
    return RSAKey.import_key(_PRIVATE_PEM)


@pytest.fixture
def rsa_public():
    return RSAKey.import_key(_PUBLIC_PEM)


class _FakeClient:
    def __init__(self, client_id, allowed_grant_types=None):
        self.client_id = client_id
        self._grant_types = allowed_grant_types or [IDJAGGrant.GRANT_TYPE]

    def check_grant_type(self, grant_type):
        return grant_type in self._grant_types


class _FakeUser:
    def __init__(self, sub):
        self.sub = sub


class _FakePayload:
    def __init__(self, grant_type, scope=None):
        self.grant_type = grant_type
        self.scope = scope


class _FakeRequest:
    def __init__(self, form, scope=None):
        self.form = form
        self.client = None
        self.user = None
        self.payload = _FakePayload(form.get("grant_type", ""), scope=scope)


class _TestIDJAGGrant(IDJAGGrant):
    TOKEN_ENDPOINT = "https://rs.example.com/token"
    _issuer_key = None
    _clients = {}
    _users = {}
    _allow_permission = True
    _jti_store = set()

    def get_audiences(self):
        return [self.TOKEN_ENDPOINT]

    def resolve_issuer_key(self, issuer, headers):
        if self._issuer_key is None:
            raise InvalidGrantError(description="Untrusted issuer")
        return self._issuer_key

    def resolve_client_by_id(self, client_id):
        return self._clients.get(client_id)

    def authenticate_user(self, subject):
        return self._users.get(subject)

    def check_jti(self, claims, jti):
        if jti in self._jti_store:
            return False
        self._jti_store.add(jti)
        return True

    def check_id_jag_permission(self, client, user, scopes):
        return self._allow_permission

    def validate_requested_scope(self):
        pass

    def save_token(self, token):
        pass

    def generate_token(self, **kwargs):
        return {"access_token": "tok_123", "token_type": "Bearer"}


@pytest.fixture(autouse=True)
def _reset(rsa_public):
    _TestIDJAGGrant._issuer_key = rsa_public
    _TestIDJAGGrant._clients = {"app-456": _FakeClient("app-456")}
    _TestIDJAGGrant._users = {"user-123": _FakeUser("user-123")}
    _TestIDJAGGrant._allow_permission = True
    _TestIDJAGGrant._jti_store = set()


def _grant(form, scope=None):
    req = _FakeRequest(form, scope=scope)
    g = _TestIDJAGGrant.__new__(_TestIDJAGGrant)
    g.request = req
    g.server = None
    return g


def _sign(rsa_private, **kw):
    defaults = dict(
        key=rsa_private,
        issuer="https://idp.example.com",
        audience="https://rs.example.com/token",
        subject="user-123",
        client_id="app-456",
        alg="RS256",
    )
    defaults.update(kw)
    return IDJAGGrant.sign(**defaults)


# === sign() ===


def test_sign_produces_valid_jwt(rsa_private, rsa_public):
    assertion = _sign(rsa_private)
    token = jwt.decode(assertion, rsa_public)
    assert token.header["typ"] == "oauth-id-jag+jwt"
    assert token.claims["client_id"] == "app-456"
    assert token.claims["sub"] == "user-123"
    assert "jti" in token.claims
    assert "iat" in token.claims


def test_sign_requires_subject(rsa_private):
    with pytest.raises(ValueError, match="subject"):
        IDJAGGrant.sign(
            rsa_private, issuer="i", audience="a",
            subject=None, client_id="c", alg="RS256",
        )


def test_sign_requires_alg(rsa_private):
    with pytest.raises(ValueError, match="alg"):
        IDJAGGrant.sign(
            rsa_private, issuer="i", audience="a",
            subject="s", client_id="c",
        )


def test_sign_custom_jti(rsa_private, rsa_public):
    assertion = _sign(rsa_private, jti="my-jti")
    token = jwt.decode(assertion, rsa_public)
    assert token.claims["jti"] == "my-jti"


def test_sign_with_extra_claims(rsa_private, rsa_public):
    assertion = IDJAGGrant.sign(
        rsa_private,
        issuer="https://idp.example.com",
        audience="https://rs.example.com/token",
        subject="user-123",
        client_id="app-456",
        alg="RS256",
        claims={"custom": "value"},
    )
    token = jwt.decode(assertion, rsa_public)
    assert token.claims["custom"] == "value"
    assert token.claims["client_id"] == "app-456"


def test_malformed_assertion_value_error(rsa_private):
    """A completely malformed assertion that causes ValueError during decode."""
    # Craft an assertion that passes initial extraction but fails jwt.decode
    # with a ValueError (e.g., corrupted key material)
    from unittest.mock import patch

    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})

    with patch("authlib.oauth2.drafts.id_jag.jwt.decode", side_effect=ValueError("bad key")):
        with pytest.raises(InvalidGrantError):
            g.validate_token_request()


# === Happy path ===


def test_valid_id_jag_flow(rsa_private):
    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    g.validate_token_request()
    assert g.request.client.client_id == "app-456"
    assert g.request.user.sub == "user-123"


def test_no_refresh_token_issued(rsa_private):
    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    g.validate_token_request()
    status, token, _ = g.create_token_response()
    assert status == 200
    assert "refresh_token" not in token


# === typ header ===


def _raw_jwt(rsa_private, header_extra=None, **claim_overrides):
    h = {"alg": "RS256"}
    if header_extra:
        h.update(header_extra)
    claims = dict(
        iss="https://idp.example.com",
        sub="user-123",
        aud="https://rs.example.com/token",
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        jti="jti-1",
        client_id="app-456",
    )
    claims.update(claim_overrides)
    return jwt.encode(h, claims, rsa_private)


def test_missing_typ_header(rsa_private):
    token_str = _raw_jwt(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError, match="typ"):
        g.validate_token_request()


def test_wrong_typ_header(rsa_private):
    token_str = _raw_jwt(rsa_private, header_extra={"typ": "JWT"})
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError, match="typ"):
        g.validate_token_request()


def test_at_jwt_typ_rejected(rsa_private):
    token_str = _raw_jwt(rsa_private, header_extra={"typ": "at+jwt"})
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError, match="typ"):
        g.validate_token_request()


# === Claims ===


def _sign_missing_claim(rsa_private, claim_to_remove):
    claims = dict(
        iss="https://idp.example.com",
        sub="user-123",
        aud="https://rs.example.com/token",
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        jti="jti-x",
        client_id="app-456",
    )
    claims.pop(claim_to_remove)
    return jwt.encode(
        {"alg": "RS256", "typ": "oauth-id-jag+jwt"}, claims, rsa_private,
    )


def test_missing_client_id_claim(rsa_private):
    token_str = _sign_missing_claim(rsa_private, "client_id")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


def test_missing_sub_claim(rsa_private):
    token_str = _sign_missing_claim(rsa_private, "sub")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


def test_missing_jti_claim(rsa_private):
    token_str = _sign_missing_claim(rsa_private, "jti")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


def test_missing_iat_claim(rsa_private):
    token_str = _sign_missing_claim(rsa_private, "iat")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


def test_missing_iss_claim(rsa_private):
    token_str = _sign_missing_claim(rsa_private, "iss")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError, match="iss"):
        g.validate_token_request()


# === Audience ===


def test_audience_mismatch(rsa_private):
    assertion = _sign(rsa_private, audience="https://wrong.example.com/token")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


# === Issuer ===


def test_untrusted_issuer(rsa_private):
    _TestIDJAGGrant._issuer_key = None
    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidGrantError, match="[Uu]ntrusted"):
        g.validate_token_request()


# === Client ===


def test_unknown_client(rsa_private):
    assertion = _sign(rsa_private, client_id="unknown")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidClientError):
        g.validate_token_request()


def test_client_id_mismatch(rsa_private):
    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    g.request.client = _FakeClient("other-client")
    with pytest.raises(InvalidGrantError, match="does not match"):
        g.validate_token_request()


def test_unauthorized_grant_type(rsa_private):
    _TestIDJAGGrant._clients["app-456"] = _FakeClient(
        "app-456", allowed_grant_types=["authorization_code"],
    )
    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(UnauthorizedClientError):
        g.validate_token_request()


# === Signature ===


def test_invalid_signature(rsa_private):
    wrong_key = RSAKey.generate_key(2048)
    assertion = _sign(wrong_key)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


# === Expiry ===


def test_expired_assertion(rsa_private):
    assertion = _sign(
        rsa_private,
        issued_at=int(time.time()) - 7200,
        expires_at=int(time.time()) - 3600,
    )
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


def test_clock_skew_within_leeway(rsa_private):
    assertion = _sign(rsa_private, expires_at=int(time.time()) - 30)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    g.validate_token_request()  # should not raise


def test_nbf_in_future(rsa_private):
    """nbf ahead of current time must be rejected (auto-handled by joserfc)."""
    token_str = jwt.encode(
        {"alg": "RS256", "typ": "oauth-id-jag+jwt"},
        dict(
            iss="https://idp.example.com",
            sub="user-123",
            aud="https://rs.example.com/token",
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="jti-nbf",
            client_id="app-456",
            nbf=int(time.time()) + 600,  # 10 minutes in the future
        ),
        rsa_private,
    )
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": token_str})
    with pytest.raises(InvalidGrantError):
        g.validate_token_request()


# === Replay ===


def test_jti_replay_rejected(rsa_private):
    assertion = _sign(rsa_private, jti="same-jti")
    g1 = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    g1.validate_token_request()

    assertion2 = _sign(rsa_private, jti="same-jti")
    g2 = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion2})
    with pytest.raises(InvalidGrantError, match="jti"):
        g2.validate_token_request()


# === Policy ===


def test_policy_denial(rsa_private):
    _TestIDJAGGrant._allow_permission = False
    assertion = _sign(rsa_private)
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidGrantError, match="[Pp]ermission"):
        g.validate_token_request()


# === Subject ===


def test_invalid_sub(rsa_private):
    assertion = _sign(rsa_private, subject="nonexistent")
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE, "assertion": assertion})
    with pytest.raises(InvalidGrantError, match="sub"):
        g.validate_token_request()


# === Missing assertion ===


def test_missing_assertion():
    g = _grant({"grant_type": IDJAGGrant.GRANT_TYPE})
    with pytest.raises(InvalidRequestError, match="assertion"):
        g.validate_token_request()


# === Dead hooks ===


def test_resolve_issuer_client_raises():
    g = _TestIDJAGGrant.__new__(_TestIDJAGGrant)
    with pytest.raises(NotImplementedError, match="resolve_client_by_id"):
        g.resolve_issuer_client("some-issuer")


def test_resolve_client_public_key_raises():
    g = _TestIDJAGGrant.__new__(_TestIDJAGGrant)
    with pytest.raises(NotImplementedError, match="resolve_issuer_key"):
        g.resolve_client_public_key(None)


def test_has_granted_permission_raises():
    g = _TestIDJAGGrant.__new__(_TestIDJAGGrant)
    with pytest.raises(NotImplementedError, match="check_id_jag_permission"):
        g.has_granted_permission(None, None)


# === Registration ===


def test_same_grant_type_as_jwt_bearer():
    assert IDJAGGrant.GRANT_TYPE == JWTBearerGrant.GRANT_TYPE
