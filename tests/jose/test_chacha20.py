import unittest

import pytest

from authlib.jose import JsonWebEncryption
from authlib.jose import OctKey
from authlib.jose.drafts import register_jwe_draft

register_jwe_draft(JsonWebEncryption)


class ChaCha20Test(unittest.TestCase):
    def test_dir_alg_c20p(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(256, is_private=True)
        protected = {"alg": "dir", "enc": "C20P"}
        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

        key2 = OctKey.generate_key(128, is_private=True)
        with pytest.raises(ValueError):
            jwe.deserialize_compact(data, key2)

        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", key2)

    def test_dir_alg_xc20p(self):
        pytest.importorskip("Cryptodome.Cipher.ChaCha20_Poly1305")

        jwe = JsonWebEncryption()
        key = OctKey.generate_key(256, is_private=True)
        protected = {"alg": "dir", "enc": "XC20P"}
        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

        key2 = OctKey.generate_key(128, is_private=True)
        with pytest.raises(ValueError):
            jwe.deserialize_compact(data, key2)

        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", key2)

    def test_xc20p_content_encryption_decryption(self):
        pytest.importorskip("Cryptodome.Cipher.ChaCha20_Poly1305")

        # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1
        enc = JsonWebEncryption.ENC_REGISTRY["XC20P"]

        plaintext = bytes.fromhex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            + "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            + "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            + "637265656e20776f756c642062652069742e"
        )
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        key = bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        iv = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")

        ciphertext, tag = enc.encrypt(plaintext, aad, iv, key)
        assert ciphertext == bytes.fromhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
            + "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
            + "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
            + "21f9664c97637da9768812f615c68b13b52e"
        )
        assert tag == bytes.fromhex("c0875924c1c7987947deafd8780acf49")

        decrypted_plaintext = enc.decrypt(ciphertext, aad, iv, tag, key)
        assert decrypted_plaintext == plaintext
