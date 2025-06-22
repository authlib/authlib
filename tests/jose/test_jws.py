import json
import unittest

import pytest

from authlib.jose import JsonWebSignature
from authlib.jose import errors
from tests.util import read_file_path


class JWSTest(unittest.TestCase):
    def test_invalid_input(self):
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

    def test_invalid_alg(self):
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

    def test_bad_signature(self):
        jws = JsonWebSignature()
        s = "eyJhbGciOiJIUzI1NiJ9.YQ.YQ"
        with pytest.raises(errors.BadSignatureError):
            jws.deserialize(s, "k")

    def test_not_supported_alg(self):
        jws = JsonWebSignature(algorithms=["HS256"])
        s = jws.serialize({"alg": "HS256"}, "hello", "secret")

        jws = JsonWebSignature(algorithms=["RS256"])
        with pytest.raises(errors.UnsupportedAlgorithmError):
            jws.serialize({"alg": "HS256"}, "hello", "secret")

        with pytest.raises(errors.UnsupportedAlgorithmError):
            jws.deserialize(s, "secret")

    def test_compact_jws(self):
        jws = JsonWebSignature(algorithms=["HS256"])
        s = jws.serialize({"alg": "HS256"}, "hello", "secret")
        data = jws.deserialize(s, "secret")
        header, payload = data["header"], data["payload"]
        assert payload == b"hello"
        assert header["alg"] == "HS256"
        assert "signature" not in data

    def test_compact_rsa(self):
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

    def test_compact_rsa_pss(self):
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

    def test_compact_none(self):
        jws = JsonWebSignature(algorithms=["none"])
        s = jws.serialize({"alg": "none"}, "hello", None)
        data = jws.deserialize(s, None)
        header, payload = data["header"], data["payload"]
        assert payload == b"hello"
        assert header["alg"] == "none"

    def test_flattened_json_jws(self):
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

    def test_nested_json_jws(self):
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

    def test_function_key(self):
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

    def test_serialize_json_empty_payload(self):
        jws = JsonWebSignature()
        protected = {"alg": "HS256"}
        header = {"protected": protected, "header": {"kid": "a"}}
        s = jws.serialize_json(header, b"", "secret")
        data = jws.deserialize_json(s, "secret")
        assert data["payload"] == b""

    def test_fail_deserialize_json(self):
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

    def test_validate_header(self):
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

    def test_ES512_alg(self):
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

    def test_ES256K_alg(self):
        jws = JsonWebSignature(algorithms=["ES256K"])
        private_key = read_file_path("secp256k1-private.pem")
        public_key = read_file_path("secp256k1-pub.pem")
        s = jws.serialize({"alg": "ES256K"}, "hello", private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data["header"], data["payload"]
        assert payload == b"hello"
        assert header["alg"] == "ES256K"
