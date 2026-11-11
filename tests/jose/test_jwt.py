import datetime
import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa

from authlib.common.encoding import json_b64encode
from authlib.common.encoding import urlsafe_b64encode
from authlib.jose import JsonWebKey
from authlib.jose import JsonWebToken
from authlib.jose import JWTClaims
from authlib.jose import OctKey
from authlib.jose import errors
from authlib.jose import jwt
from authlib.jose.errors import UnsupportedAlgorithmError
from authlib.jose.rfc7518.oct_key import _SSH_PUBLIC_PREFIXES
from tests.util import read_file_path


def test_init_algorithms():
    _jwt = JsonWebToken(["RS256"])
    with pytest.raises(UnsupportedAlgorithmError):
        _jwt.encode({"alg": "HS256"}, {}, "k")

    _jwt = JsonWebToken("RS256")
    with pytest.raises(UnsupportedAlgorithmError):
        _jwt.encode({"alg": "HS256"}, {}, "k")


@pytest.mark.parametrize("prefix", ["", "\n", " \t\r\n", "# public key\n", "\ufeff"])
@pytest.mark.parametrize("key_format", ["raw", "jwk", "key"])
def test_reject_pem_key_as_hmac_secret(prefix, key_format):
    public_key = prefix + read_file_path("rsa_public.pem")
    private_key = read_file_path("rsa_private.pem")
    signed = jwt.encode({"alg": "RS256"}, {"sub": "alice"}, private_key)
    assert jwt.decode(signed, public_key)["sub"] == "alice"

    raw_key = public_key.encode()
    signing_input = (
        json_b64encode({"alg": "HS256"}) + b"." + json_b64encode({"sub": "attacker"})
    )
    signature = hmac.new(raw_key, signing_input, hashlib.sha256).digest()
    forged = signing_input + b"." + urlsafe_b64encode(signature)

    key = public_key
    if key_format != "raw":
        key = {"kty": "oct", "k": urlsafe_b64encode(raw_key).decode()}
        if key_format == "key":
            key = OctKey.import_key(key)

    with pytest.raises(ValueError, match="This key may not be safe to import"):
        jwt.decode(forged, key)


def _ssh_certificate(private_key):
    """Return an OpenSSH certificate for the public key."""
    ca = ed25519.Ed25519PrivateKey.generate()
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    certificate = (
        serialization.SSHCertificateBuilder()
        .public_key(private_key.public_key())
        .serial(1)
        .type(serialization.SSHCertificateType.USER)
        .key_id(b"alice")
        .valid_principals([b"alice"])
        .valid_after(now - 60)
        .valid_before(now + 3600)
        .sign(ca)
    )
    return certificate.public_bytes()


@pytest.fixture(scope="module", params=["rsa", "ec", "ed25519"])
def ssh_key_pair(request):
    """Return a private key, its JWS algorithm and its SSH key type."""
    if request.param == "rsa":
        return rsa.generate_private_key(65537, 2048), "RS256", b"ssh-rsa"

    if request.param == "ec":
        return ec.generate_private_key(ec.SECP256R1()), "ES256", b"ecdsa-sha2-nistp256"

    return ed25519.Ed25519PrivateKey.generate(), "EdDSA", b"ssh-ed25519"


@pytest.mark.parametrize("key_form", ["tab", "tab-space", "certificate"])
@pytest.mark.parametrize("key_format", ["raw", "jwk", "key"])
def test_reject_ssh_key_as_hmac_secret(ssh_key_pair, key_form, key_format):
    """An SSH public key or certificate that verifies tokens is refused as an
    HMAC secret."""
    private_key, alg, ssh_type = ssh_key_pair
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    if key_form == "tab":
        public_key = public_key.replace(ssh_type + b" ", ssh_type + b"\t", 1)
    elif key_form == "tab-space":
        public_key = public_key.replace(ssh_type + b" ", ssh_type + b"\t ", 1)
    else:
        public_key = _ssh_certificate(private_key)

    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    signed = jwt.encode({"alg": alg}, {"sub": "alice"}, pem)
    assert jwt.decode(signed, public_key)["sub"] == "alice"

    signing_input = (
        json_b64encode({"alg": "HS256"}) + b"." + json_b64encode({"sub": "attacker"})
    )
    signature = hmac.new(public_key, signing_input, hashlib.sha256).digest()
    forged = signing_input + b"." + urlsafe_b64encode(signature)

    key = public_key
    if key_format != "raw":
        key = {"kty": "oct", "k": urlsafe_b64encode(public_key).decode()}
        if key_format == "key":
            key = OctKey.import_key(key)

    with pytest.raises(ValueError, match="This key may not be safe to import"):
        jwt.decode(forged, key)


@pytest.mark.parametrize(
    "key_class",
    [
        cls
        for cls in JsonWebKey.JWK_KEY_CLS.values()
        if getattr(cls, "SSH_PUBLIC_PREFIX", None)
    ],
    ids=lambda cls: cls.kty,
)
def test_ssh_prefixes_are_checked(key_class):
    """Every SSH key type loaded by an asymmetric key class is checked before
    a key is accepted as an HMAC secret."""
    assert key_class.SSH_PUBLIC_PREFIX in _SSH_PUBLIC_PREFIXES


@pytest.mark.parametrize(
    "secret",
    [
        b"ssh-rsa-signing-secret-0123456789",
        b"ssh-rsa-deploy key for prod 0123456789",
        b"ssh-ed25519_rotation\tsecret_0123456789",
        b"ssh-ed25519\tsecret_value_0123456789",
    ],
)
def test_accept_secret_starting_like_ssh_key_type(secret):
    """A secret that only starts like an SSH key type is still accepted."""
    token = jwt.encode({"alg": "HS256"}, {"sub": "alice"}, secret)
    assert jwt.decode(token, secret)["sub"] == "alice"


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
@pytest.mark.parametrize(
    "key",
    [
        b"",
        "",
        {"kty": "oct", "k": ""},
        OctKey.import_key({"kty": "oct", "k": ""}),
        lambda header, payload: "",
    ],
    ids=["bytes", "str", "jwk", "key", "callable"],
)
def test_reject_empty_hmac_key(alg, key):
    hash_alg = getattr(hashlib, f"sha{alg[2:]}")
    signing_input = (
        json_b64encode({"alg": alg}) + b"." + json_b64encode({"sub": "attacker"})
    )
    signature = hmac.new(b"", signing_input, hash_alg).digest()
    forged = signing_input + b"." + urlsafe_b64encode(signature)

    with pytest.raises(ValueError, match="must not be empty"):
        jwt.decode(forged, key)

    with pytest.raises(ValueError, match="must not be empty"):
        jwt.encode({"alg": alg}, {"sub": "alice"}, key)


def test_encode_sensitive_data():
    # check=False won't raise error
    jwt.encode({"alg": "HS256"}, {"password": ""}, "k", check=False)
    with pytest.raises(errors.InsecureClaimError):
        jwt.encode(
            {"alg": "HS256"},
            {"password": ""},
            "k",
        )
    with pytest.raises(errors.InsecureClaimError):
        jwt.encode(
            {"alg": "HS256"},
            {"text": "4242424242424242"},
            "k",
        )


def test_encode_datetime():
    now = datetime.datetime.now(tz=datetime.UTC)
    id_token = jwt.encode({"alg": "HS256"}, {"exp": now}, "k")
    claims = jwt.decode(id_token, "k")
    assert isinstance(claims.exp, int)


def test_validate_essential_claims():
    id_token = jwt.encode({"alg": "HS256"}, {"iss": "foo"}, "k")
    claims_options = {"iss": {"essential": True, "values": ["foo"]}}
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    claims.validate()

    claims.options = {"sub": {"essential": True}}
    with pytest.raises(errors.MissingClaimError):
        claims.validate()


def test_attribute_error():
    claims = JWTClaims({"iss": "foo"}, {"alg": "HS256"})
    with pytest.raises(AttributeError):
        claims.invalid  # noqa: B018


def test_invalid_values():
    id_token = jwt.encode({"alg": "HS256"}, {"iss": "foo"}, "k")
    claims_options = {"iss": {"values": ["bar"]}}
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()
    claims.options = {"iss": {"value": "bar"}}
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()


def test_validate_expected_issuer_received_None():
    id_token = jwt.encode({"alg": "HS256"}, {"iss": None, "sub": None}, "k")
    claims_options = {"iss": {"essential": True, "values": ["foo"]}}
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()


def test_validate_aud():
    id_token = jwt.encode({"alg": "HS256"}, {"aud": "foo"}, "k")
    claims_options = {"aud": {"essential": True, "value": "foo"}}
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    claims.validate()

    claims.options = {"aud": {"values": ["bar"]}}
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()

    id_token = jwt.encode({"alg": "HS256"}, {"aud": ["foo", "bar"]}, "k")
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    claims.validate()
    # no validate
    claims.options = {"aud": {"values": []}}
    claims.validate()


def test_validate_exp():
    id_token = jwt.encode({"alg": "HS256"}, {"exp": "invalid"}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()

    id_token = jwt.encode({"alg": "HS256"}, {"exp": 1234}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(errors.ExpiredTokenError):
        claims.validate()


def test_validate_nbf():
    id_token = jwt.encode({"alg": "HS256"}, {"nbf": "invalid"}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()

    id_token = jwt.encode({"alg": "HS256"}, {"nbf": 1234}, "k")
    claims = jwt.decode(id_token, "k")
    claims.validate()

    id_token = jwt.encode({"alg": "HS256"}, {"nbf": 1234}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(errors.InvalidTokenError):
        claims.validate(123)


def test_validate_iat_issued_in_future():
    in_future = datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(seconds=10)
    id_token = jwt.encode({"alg": "HS256"}, {"iat": in_future}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(
        errors.InvalidTokenError,
        match="The token is not valid as it was issued in the future",
    ):
        claims.validate()


def test_validate_iat_issued_in_future_with_insufficient_leeway():
    in_future = datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(seconds=10)
    id_token = jwt.encode({"alg": "HS256"}, {"iat": in_future}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(
        errors.InvalidTokenError,
        match="The token is not valid as it was issued in the future",
    ):
        claims.validate(leeway=5)


def test_validate_iat_issued_in_future_with_sufficient_leeway():
    in_future = datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(seconds=10)
    id_token = jwt.encode({"alg": "HS256"}, {"iat": in_future}, "k")
    claims = jwt.decode(id_token, "k")
    claims.validate(leeway=20)


def test_validate_iat_issued_in_past():
    in_future = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(seconds=10)
    id_token = jwt.encode({"alg": "HS256"}, {"iat": in_future}, "k")
    claims = jwt.decode(id_token, "k")
    claims.validate()


def test_validate_iat():
    id_token = jwt.encode({"alg": "HS256"}, {"iat": "invalid"}, "k")
    claims = jwt.decode(id_token, "k")
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()


def test_validate_numeric_date_rejects_bool():
    for name in ("exp", "nbf", "iat"):
        for value in (True, False):
            id_token = jwt.encode({"alg": "HS256"}, {name: value}, "k")
            claims = jwt.decode(id_token, "k")
            with pytest.raises(errors.InvalidClaimError):
                claims.validate()


def test_validate_jti():
    id_token = jwt.encode({"alg": "HS256"}, {"jti": "bar"}, "k")
    claims_options = {"jti": {"validate": lambda c, o: o == "foo"}}
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()


def test_validate_custom():
    id_token = jwt.encode({"alg": "HS256"}, {"custom": "foo"}, "k")
    claims_options = {"custom": {"validate": lambda c, o: o == "bar"}}
    claims = jwt.decode(id_token, "k", claims_options=claims_options)
    with pytest.raises(errors.InvalidClaimError):
        claims.validate()


def test_use_jws():
    payload = {"name": "hi"}
    private_key = read_file_path("rsa_private.pem")
    pub_key = read_file_path("rsa_public.pem")
    data = jwt.encode({"alg": "RS256"}, payload, private_key)
    assert data.count(b".") == 2

    claims = jwt.decode(data, pub_key)
    assert claims["name"] == "hi"


def test_use_jwe():
    payload = {"name": "hi"}
    private_key = read_file_path("rsa_private.pem")
    pub_key = read_file_path("rsa_public.pem")
    _jwt = JsonWebToken(["RSA-OAEP", "A256GCM"])
    data = _jwt.encode({"alg": "RSA-OAEP", "enc": "A256GCM"}, payload, pub_key)
    assert data.count(b".") == 4

    claims = _jwt.decode(data, private_key)
    assert claims["name"] == "hi"


def test_use_jwks():
    header = {"alg": "RS256", "kid": "abc"}
    payload = {"name": "hi"}
    private_key = read_file_path("jwks_private.json")
    pub_key = read_file_path("jwks_public.json")
    data = jwt.encode(header, payload, private_key)
    assert data.count(b".") == 2
    claims = jwt.decode(data, pub_key)
    assert claims["name"] == "hi"


def test_use_jwks_single_kid():
    """Test that jwks can be decoded if a kid for decoding is given and encoded data has no kid and only one key is set."""
    header = {"alg": "RS256"}
    payload = {"name": "hi"}
    private_key = read_file_path("jwks_single_private.json")
    pub_key = read_file_path("jwks_single_public.json")
    data = jwt.encode(header, payload, private_key)
    assert data.count(b".") == 2
    claims = jwt.decode(data, pub_key)
    assert claims["name"] == "hi"


# Added a unit test to showcase my problem.
# This calls jwt.decode similarly as is done in parse_id_token method of the AsyncOpenIDMixin class when the id token does not contain a kid in the alg header.
def test_use_jwks_single_kid_keyset():
    """Test that jwks can be decoded if a kid for decoding is given and encoded data has no kid and a keyset with one key."""
    header = {"alg": "RS256"}
    payload = {"name": "hi"}
    private_key = read_file_path("jwks_single_private.json")
    pub_key = read_file_path("jwks_single_public.json")
    data = jwt.encode(header, payload, private_key)
    assert data.count(b".") == 2
    claims = jwt.decode(data, JsonWebKey.import_key_set(pub_key))
    assert claims["name"] == "hi"


def test_with_ec():
    payload = {"name": "hi"}
    private_key = read_file_path("secp521r1-private.json")
    pub_key = read_file_path("secp521r1-public.json")
    data = jwt.encode({"alg": "ES512"}, payload, private_key)
    assert data.count(b".") == 2

    claims = jwt.decode(data, pub_key)
    assert claims["name"] == "hi"
