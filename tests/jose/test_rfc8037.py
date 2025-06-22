import unittest

from authlib.jose import JsonWebSignature
from tests.util import read_file_path


class EdDSATest(unittest.TestCase):
    def test_EdDSA_alg(self):
        jws = JsonWebSignature(algorithms=["EdDSA"])
        private_key = read_file_path("ed25519-pkcs8.pem")
        public_key = read_file_path("ed25519-pub.pem")
        s = jws.serialize({"alg": "EdDSA"}, "hello", private_key)
        data = jws.deserialize(s, public_key)
        header, payload = data["header"], data["payload"]
        assert payload == b"hello"
        assert header["alg"] == "EdDSA"
