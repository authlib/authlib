import json

import pytest

from authlib.jose import JsonWebSignature
from authlib.jose import errors
from tests.util import read_file_path
import base64
import hmac
import hashlib


def test_invalid_input():
    jws = JsonWebSignature()
    with pytest.raises(errors.DecodeError):
        jws.deserialize("a", "k")
    with pytest.raises(errors.DecodeError):
        jws.deserialize("a.b.c", "k")
    with pytest.raises(errors.DecodeError):
        jws.deserialize("YQ.YQ.YQ", "k")  # a
    with pytest.raises(errors.DecodeError):
        jws.deserialize("W10.a.YQ", "k")  # []
    with pytest.raises(errors.DecodeError):
        jws.deserialize("e30.a.YQ", "k")  # {}
    with pytest.raises(errors.DecodeError):
        jws.deserialize("eyJhbGciOiJzIn0.a.YQ", "k")
    with pytest.raises(errors.DecodeError):
        jws.deserialize("eyJhbGciOiJzIn0.YQ.a", "k")


def test_invalid_alg():
    jws = JsonWebSignature()
    with pytest.raises(errors.UnsupportedAlgorithmError):
        jws.deserialize(
            "eyJhbGciOiJzIn0.YQ.YQ",
            "k",
        )
    with pytest.raises(errors.MissingAlgorithmError):
        jws.serialize({}, "", "k")
    with pytest.raises(errors.UnsupportedAlgorithmError):
        jws.serialize({"alg": "s"}, "", "k")


def test_bad_signature():
    jws = JsonWebSignature()
    s = "eyJhbGciOiJIUzI1NiJ9.YQ.YQ"
    with pytest.raises(errors.BadSignatureError):
        jws.deserialize(s, "k")


def test_not_supported_alg():
    jws = JsonWebSignature(algorithms=["HS256"])
    s = jws.serialize({"alg": "HS256"}, "hello", "secret")

    jws = JsonWebSignature(algorithms=["RS256"])
    with pytest.raises(errors.UnsupportedAlgorithmError):
        jws.serialize({"alg": "HS256"}, "hello", "secret")

    with pytest.raises(errors.UnsupportedAlgorithmError):
        jws.deserialize(s, "secret")


def test_compact_jws():
    jws = JsonWebSignature(algorithms=["HS256"])
    s = jws.serialize({"alg": "HS256"}, "hello", "secret")
    data = jws.deserialize(s, "secret")
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "HS256"
    assert "signature" not in data


def test_compact_rsa():
    jws = JsonWebSignature()
    private_key = read_file_path("rsa_private.pem")
    public_key = read_file_path("rsa_public.pem")
    s = jws.serialize({"alg": "RS256"}, "hello", private_key)
    data = jws.deserialize(s, public_key)
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "RS256"

    # can deserialize with private key
    data2 = jws.deserialize(s, private_key)
    assert data == data2

    ssh_pub_key = read_file_path("ssh_public.pem")
    with pytest.raises(errors.BadSignatureError):
        jws.deserialize(s, ssh_pub_key)


def test_compact_rsa_pss():
    jws = JsonWebSignature()
    private_key = read_file_path("rsa_private.pem")
    public_key = read_file_path("rsa_public.pem")
    s = jws.serialize({"alg": "PS256"}, "hello", private_key)
    data = jws.deserialize(s, public_key)
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "PS256"
    ssh_pub_key = read_file_path("ssh_public.pem")
    with pytest.raises(errors.BadSignatureError):
        jws.deserialize(s, ssh_pub_key)


def test_compact_none():
    jws = JsonWebSignature(algorithms=["none"])
    s = jws.serialize({"alg": "none"}, "hello", None)
    data = jws.deserialize(s, None)
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "none"


def test_flattened_json_jws():
    jws = JsonWebSignature()
    protected = {"alg": "HS256"}
    header = {"protected": protected, "header": {"kid": "a"}}
    s = jws.serialize(header, "hello", "secret")
    assert isinstance(s, dict)

    data = jws.deserialize(s, "secret")
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "HS256"
    assert "protected" not in data


def test_nested_json_jws():
    jws = JsonWebSignature()
    protected = {"alg": "HS256"}
    header = {"protected": protected, "header": {"kid": "a"}}
    s = jws.serialize([header], "hello", "secret")
    assert isinstance(s, dict)
    assert "signatures" in s

    data = jws.deserialize(s, "secret")
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header[0]["alg"] == "HS256"
    assert "signatures" not in data

    # test bad signature
    with pytest.raises(errors.BadSignatureError):
        jws.deserialize(s, "f")


def test_function_key():
    protected = {"alg": "HS256"}
    header = [
        {"protected": protected, "header": {"kid": "a"}},
        {"protected": protected, "header": {"kid": "b"}},
    ]

    def load_key(header, payload):
        assert payload == b"hello"
        kid = header.get("kid")
        if kid == "a":
            return "secret-a"
        return "secret-b"

    jws = JsonWebSignature()
    s = jws.serialize(header, b"hello", load_key)
    assert isinstance(s, dict)
    assert "signatures" in s

    data = jws.deserialize(json.dumps(s), load_key)
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header[0]["alg"] == "HS256"
    assert "signature" not in data


def test_serialize_json_empty_payload():
    jws = JsonWebSignature()
    protected = {"alg": "HS256"}
    header = {"protected": protected, "header": {"kid": "a"}}
    s = jws.serialize_json(header, b"", "secret")
    data = jws.deserialize_json(s, "secret")
    assert data["payload"] == b""


def test_fail_deserialize_json():
    jws = JsonWebSignature()
    with pytest.raises(errors.DecodeError):
        jws.deserialize_json(None, "")
    with pytest.raises(errors.DecodeError):
        jws.deserialize_json("[]", "")
    with pytest.raises(errors.DecodeError):
        jws.deserialize_json("{}", "")

    # missing protected
    s = json.dumps({"payload": "YQ"})
    with pytest.raises(errors.DecodeError):
        jws.deserialize_json(s, "")

    # missing signature
    s = json.dumps({"payload": "YQ", "protected": "YQ"})
    with pytest.raises(errors.DecodeError):
        jws.deserialize_json(s, "")


def test_serialize_json_overwrite_header():
    jws = JsonWebSignature()
    protected = {"alg": "HS256", "kid": "a"}
    header = {"protected": protected}
    result = jws.serialize_json(header, b"", "secret")
    result["header"] = {"kid": "b"}
    decoded = jws.deserialize_json(result, "secret")
    assert decoded["header"]["kid"] == "a"


def test_validate_header():
    jws = JsonWebSignature(private_headers=[])
    protected = {"alg": "HS256", "invalid": "k"}
    header = {"protected": protected, "header": {"kid": "a"}}
    with pytest.raises(errors.InvalidHeaderParameterNameError):
        jws.serialize(
            header,
            b"hello",
            "secret",
        )
    jws = JsonWebSignature(private_headers=["invalid"])
    s = jws.serialize(header, b"hello", "secret")
    assert isinstance(s, dict)

    jws = JsonWebSignature()
    s = jws.serialize(header, b"hello", "secret")
    assert isinstance(s, dict)


def test_validate_crit_header_with_serialize():
    jws = JsonWebSignature()
    protected = {"alg": "HS256", "kid": "1", "crit": ["kid"]}
    jws.serialize(protected, b"hello", "secret")

    protected = {"alg": "HS256", "crit": ["kid"]}
    with pytest.raises(errors.InvalidCritHeaderParameterNameError):
        jws.serialize(protected, b"hello", "secret")

    protected = {"alg": "HS256", "invalid": "1", "crit": ["invalid"]}
    with pytest.raises(errors.InvalidCritHeaderParameterNameError):
        jws.serialize(protected, b"hello", "secret")


def test_validate_crit_header_with_deserialize():
    jws = JsonWebSignature()
    case1 = "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsia2lkIl19.aGVsbG8.RVimhJH2LRGAeHy0ZcbR9xsgKhzhxIBkHs7S_TDgWvc"
    with pytest.raises(errors.InvalidCritHeaderParameterNameError):
        jws.deserialize(case1, "secret")

    case2 = (
        "eyJhbGciOiJIUzI1NiIsImludmFsaWQiOiIxIiwiY3JpdCI6WyJpbnZhbGlkIl19."
        "aGVsbG8.ifW_D1AQWzggrpd8npcnmpiwMD9dp5FTX66lCkYFENM"
    )
    with pytest.raises(errors.InvalidCritHeaderParameterNameError):
        jws.deserialize(case2, "secret")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _sign_flattened(protected: dict, header: dict, payload_bytes: bytes, key: str) -> dict:
    protected_bytes = json.dumps(protected).encode()
    signing_input = f"{_b64url(protected_bytes)}.{_b64url(payload_bytes)}".encode(
    )
    sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    obj = {
        "payload": _b64url(payload_bytes),
        "protected": _b64url(protected_bytes),
        "signature": _b64url(sig),
    }
    if header:
        obj["header"] = header
    return obj


def test_json_flattened_rejects_unprotected_crit():
    jws = JsonWebSignature()
    payload = b"hello"
    # crit incorrectly placed in unprotected header
    obj = _sign_flattened(
        {"alg": "HS256"}, {"crit": ["bork"], "bork": "x"}, payload, "secret")
    with pytest.raises(errors.InvalidHeaderParameterNameError):
        jws.deserialize_json(obj, "secret")


def test_json_flattened_rejects_protected_unknown_crit():
    jws = JsonWebSignature()
    payload = b"hello"
    # Unknown critical header name listed in protected crit
    obj = _sign_flattened(
        {"alg": "HS256", "crit": ["bork"], "bork": "x"}, {}, payload, "secret")
    with pytest.raises(errors.InvalidCritHeaderParameterNameError):
        jws.deserialize_json(obj, "secret")


def test_json_flattened_rejects_protected_missing_header():
    jws = JsonWebSignature()
    payload = b"hello"
    # 'kid' listed in crit but not present in protected header
    obj = _sign_flattened(
        {"alg": "HS256", "crit": ["kid"]}, {}, payload, "secret")
    with pytest.raises(errors.InvalidCritHeaderParameterNameError):
        jws.deserialize_json(obj, "secret")


def test_json_flattened_accepts_allowlisted_crit():
    # Allowlist 'cnf' so protected crit:["cnf"] is accepted
    jws = JsonWebSignature(private_headers=["cnf"])
    payload = b"hello"
    obj = _sign_flattened(
        {"alg": "HS256", "crit": ["cnf"], "cnf": {"jkt": "thumb-42"}},
        {},
        payload,
        "secret",
    )
    out = jws.deserialize_json(obj, "secret")
    assert out["payload"] == payload


def test_json_nested_rejects_unprotected_crit_in_any_signature():
    jws = JsonWebSignature()
    payload = b"hello"
    # Build two signature entries: one valid, one with unprotected crit
    good = _sign_flattened({"alg": "HS256"}, {"kid": "a"}, payload, "secret")
    bad = _sign_flattened(
        {"alg": "HS256"}, {"crit": ["bork"], "bork": "x"}, payload, "secret")
    obj = {"payload": good["payload"], "signatures": [
        {"protected": good["protected"], "header": {
            "kid": "a"}, "signature": good["signature"]},
        {"protected": bad["protected"], "header": {
            "crit": ["bork"], "bork": "x"}, "signature": bad["signature"]},
    ]}
    with pytest.raises(errors.InvalidHeaderParameterNameError):
        jws.deserialize_json(obj, "secret")


def test_json_flattened_rejects_invalid_crit_type():
    jws = JsonWebSignature()
    payload = b"hello"
    # crit must be an array of strings
    obj = _sign_flattened(
        {"alg": "HS256", "crit": "kid"}, {}, payload, "secret")
    with pytest.raises(errors.InvalidHeaderParameterNameError):
        jws.deserialize_json(obj, "secret")
    obj = _sign_flattened({"alg": "HS256", "crit": [1]}, {}, payload, "secret")
    with pytest.raises(errors.InvalidHeaderParameterNameError):
        jws.deserialize_json(obj, "secret")


def test_ES512_alg():
    jws = JsonWebSignature()
    private_key = read_file_path("secp521r1-private.json")
    public_key = read_file_path("secp521r1-public.json")
    with pytest.raises(ValueError):
        jws.serialize({"alg": "ES256"}, "hello", private_key)
    s = jws.serialize({"alg": "ES512"}, "hello", private_key)
    data = jws.deserialize(s, public_key)
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "ES512"


def test_ES256K_alg():
    jws = JsonWebSignature(algorithms=["ES256K"])
    private_key = read_file_path("secp256k1-private.pem")
    public_key = read_file_path("secp256k1-pub.pem")
    s = jws.serialize({"alg": "ES256K"}, "hello", private_key)
    data = jws.deserialize(s, public_key)
    header, payload = data["header"], data["payload"]
    assert payload == b"hello"
    assert header["alg"] == "ES256K"
