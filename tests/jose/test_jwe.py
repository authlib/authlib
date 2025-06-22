import json
import os
import unittest

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from authlib.common.encoding import json_b64encode
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode
from authlib.jose import JsonWebEncryption
from authlib.jose import OctKey
from authlib.jose import OKPKey
from authlib.jose import errors
from authlib.jose.drafts import register_jwe_draft
from authlib.jose.errors import DecodeError
from authlib.jose.errors import InvalidAlgorithmForMultipleRecipientsMode
from authlib.jose.errors import InvalidHeaderParameterNameError
from authlib.jose.util import extract_header
from tests.util import read_file_path

register_jwe_draft(JsonWebEncryption)


class JWETest(unittest.TestCase):
    def test_not_enough_segments(self):
        s = "a.b.c"
        jwe = JsonWebEncryption()
        with pytest.raises(errors.DecodeError):
            jwe.deserialize_compact(s, None)

    def test_invalid_header(self):
        jwe = JsonWebEncryption()
        public_key = read_file_path("rsa_public.pem")
        with pytest.raises(errors.MissingAlgorithmError):
            jwe.serialize_compact({}, "a", public_key)
        with pytest.raises(errors.UnsupportedAlgorithmError):
            jwe.serialize_compact(
                {"alg": "invalid"},
                "a",
                public_key,
            )
        with pytest.raises(errors.MissingEncryptionAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA-OAEP"},
                "a",
                public_key,
            )
        with pytest.raises(errors.UnsupportedEncryptionAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA-OAEP", "enc": "invalid"},
                "a",
                public_key,
            )
        with pytest.raises(errors.UnsupportedCompressionAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA-OAEP", "enc": "A256GCM", "zip": "invalid"},
                "a",
                public_key,
            )

    def test_not_supported_alg(self):
        public_key = read_file_path("rsa_public.pem")
        private_key = read_file_path("rsa_private.pem")

        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {"alg": "RSA-OAEP", "enc": "A256GCM"}, "hello", public_key
        )

        jwe = JsonWebEncryption(algorithms=["RSA1_5", "A256GCM"])
        with pytest.raises(errors.UnsupportedAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA-OAEP", "enc": "A256GCM"},
                "hello",
                public_key,
            )
        with pytest.raises(errors.UnsupportedCompressionAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA1_5", "enc": "A256GCM", "zip": "DEF"},
                "hello",
                public_key,
            )
        with pytest.raises(errors.UnsupportedAlgorithmError):
            jwe.deserialize_compact(
                s,
                private_key,
            )

        jwe = JsonWebEncryption(algorithms=["RSA-OAEP", "A192GCM"])
        with pytest.raises(errors.UnsupportedEncryptionAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA-OAEP", "enc": "A256GCM"},
                "hello",
                public_key,
            )
        with pytest.raises(errors.UnsupportedCompressionAlgorithmError):
            jwe.serialize_compact(
                {"alg": "RSA-OAEP", "enc": "A192GCM", "zip": "DEF"},
                "hello",
                public_key,
            )
        with pytest.raises(errors.UnsupportedEncryptionAlgorithmError):
            jwe.deserialize_compact(
                s,
                private_key,
            )

    def test_inappropriate_sender_key_for_serialize_compact(self):
        jwe = JsonWebEncryption()
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg",
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }

        protected = {"alg": "ECDH-1PU", "enc": "A256GCM"}
        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", bob_key)

        protected = {"alg": "ECDH-ES", "enc": "A256GCM"}
        with pytest.raises(ValueError):
            jwe.serialize_compact(
                protected,
                b"hello",
                bob_key,
                sender_key=alice_key,
            )

    def test_inappropriate_sender_key_for_deserialize_compact(self):
        jwe = JsonWebEncryption()
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg",
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }

        protected = {"alg": "ECDH-1PU", "enc": "A256GCM"}
        data = jwe.serialize_compact(protected, b"hello", bob_key, sender_key=alice_key)
        with pytest.raises(ValueError):
            jwe.deserialize_compact(data, bob_key)

        protected = {"alg": "ECDH-ES", "enc": "A256GCM"}
        data = jwe.serialize_compact(protected, b"hello", bob_key)
        with pytest.raises(ValueError):
            jwe.deserialize_compact(data, bob_key, sender_key=alice_key)

    def test_compact_rsa(self):
        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {"alg": "RSA-OAEP", "enc": "A256GCM"},
            "hello",
            read_file_path("rsa_public.pem"),
        )
        data = jwe.deserialize_compact(s, read_file_path("rsa_private.pem"))
        header, payload = data["header"], data["payload"]
        assert payload == b"hello"
        assert header["alg"] == "RSA-OAEP"

    def test_with_zip_header(self):
        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {"alg": "RSA-OAEP", "enc": "A128CBC-HS256", "zip": "DEF"},
            "hello",
            read_file_path("rsa_public.pem"),
        )
        data = jwe.deserialize_compact(s, read_file_path("rsa_private.pem"))
        header, payload = data["header"], data["payload"]
        assert payload == b"hello"
        assert header["alg"] == "RSA-OAEP"

    def test_aes_jwe(self):
        jwe = JsonWebEncryption()
        sizes = [128, 192, 256]
        _enc_choices = [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ]
        for s in sizes:
            alg = f"A{s}KW"
            key = os.urandom(s // 8)
            for enc in _enc_choices:
                protected = {"alg": alg, "enc": enc}
                data = jwe.serialize_compact(protected, b"hello", key)
                rv = jwe.deserialize_compact(data, key)
                assert rv["payload"] == b"hello"

    def test_aes_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {"alg": "A128KW", "enc": "A128GCM"}
        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", b"invalid-key")

    def test_aes_gcm_jwe(self):
        jwe = JsonWebEncryption()
        sizes = [128, 192, 256]
        _enc_choices = [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ]
        for s in sizes:
            alg = f"A{s}GCMKW"
            key = os.urandom(s // 8)
            for enc in _enc_choices:
                protected = {"alg": alg, "enc": enc}
                data = jwe.serialize_compact(protected, b"hello", key)
                rv = jwe.deserialize_compact(data, key)
                assert rv["payload"] == b"hello"

    def test_aes_gcm_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {"alg": "A128GCMKW", "enc": "A128GCM"}
        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", b"invalid-key")

    def test_serialize_compact_fails_if_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM", "foo": "bar"}

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.serialize_compact(
                protected,
                b"hello",
                key,
            )

    def test_serialize_compact_allows_unknown_fields_in_header_while_private_fields_not_restricted(
        self,
    ):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM", "foo": "bar"}

        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

    def test_serialize_json_fails_if_protected_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM", "foo": "bar"}
        header_obj = {"protected": protected}

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.serialize_json(
                header_obj,
                b"hello",
                key,
            )

    def test_serialize_json_fails_if_unprotected_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        unprotected = {"foo": "bar"}
        header_obj = {"protected": protected, "unprotected": unprotected}

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.serialize_json(
                header_obj,
                b"hello",
                key,
            )

    def test_serialize_json_fails_if_recipient_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        recipients = [{"header": {"foo": "bar"}}]
        header_obj = {"protected": protected, "recipients": recipients}

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.serialize_json(
                header_obj,
                b"hello",
                key,
            )

    def test_serialize_json_allows_unknown_fields_in_headers_while_private_fields_not_restricted(
        self,
    ):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM", "foo1": "bar1"}
        unprotected = {"foo2": "bar2"}
        recipients = [{"header": {"foo3": "bar3"}}]
        header_obj = {
            "protected": protected,
            "unprotected": unprotected,
            "recipients": recipients,
        }

        data = jwe.serialize_json(header_obj, b"hello", key)
        rv = jwe.deserialize_json(data, key)
        assert rv["payload"] == b"hello"

    def test_serialize_json_ignores_additional_members_in_recipients_elements(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}

        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

    def test_deserialize_json_fails_if_protected_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        header_obj = {"protected": protected}

        data = jwe.serialize_json(header_obj, b"hello", key)

        decoded_protected = extract_header(to_bytes(data["protected"]), DecodeError)
        decoded_protected["foo"] = "bar"
        data["protected"] = to_unicode(json_b64encode(decoded_protected))

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.deserialize_json(data, key)

    def test_deserialize_json_fails_if_unprotected_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        header_obj = {"protected": protected}

        data = jwe.serialize_json(header_obj, b"hello", key)

        data["unprotected"] = {"foo": "bar"}

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.deserialize_json(data, key)

    def test_deserialize_json_fails_if_recipient_header_contains_unknown_field_while_private_fields_restricted(
        self,
    ):
        jwe = JsonWebEncryption(private_headers=set())
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        header_obj = {"protected": protected}

        data = jwe.serialize_json(header_obj, b"hello", key)

        data["recipients"][0]["header"] = {"foo": "bar"}

        with pytest.raises(InvalidHeaderParameterNameError):
            jwe.deserialize_json(data, key)

    def test_deserialize_json_allows_unknown_fields_in_headers_while_private_fields_not_restricted(
        self,
    ):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        header_obj = {"protected": protected}

        data = jwe.serialize_json(header_obj, b"hello", key)

        data["unprotected"] = {"foo1": "bar1"}
        data["recipients"][0]["header"] = {"foo2": "bar2"}

        rv = jwe.deserialize_json(data, key)
        assert rv["payload"] == b"hello"

    def test_deserialize_json_ignores_additional_members_in_recipients_elements(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        header_obj = {"protected": protected}

        data = jwe.serialize_json(header_obj, b"hello", key)

        data["recipients"][0]["foo"] = "bar"

        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

    def test_deserialize_json_ignores_additional_members_in_jwe_message(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"}
        header_obj = {"protected": protected}

        data = jwe.serialize_json(header_obj, b"hello", key)

        data["foo"] = "bar"

        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

    def test_ecdh_es_key_agreement_computation(self):
        # https://tools.ietf.org/html/rfc7518#appendix-C
        alice_ephemeral_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
        }
        bob_static_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }

        headers = {
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            },
        }

        alg = JsonWebEncryption.ALG_REGISTRY["ECDH-ES"]
        enc = JsonWebEncryption.ENC_REGISTRY["A128GCM"]

        alice_ephemeral_key = alg.prepare_key(alice_ephemeral_key)
        bob_static_key = alg.prepare_key(bob_static_key)

        alice_ephemeral_pubkey = alice_ephemeral_key.get_op_key("wrapKey")
        bob_static_pubkey = bob_static_key.get_op_key("wrapKey")

        # Derived key computation at Alice

        # Step-by-step methods verification
        _shared_key_at_alice = alice_ephemeral_key.exchange_shared_key(
            bob_static_pubkey
        )
        assert _shared_key_at_alice == bytes(
            [
                158,
                86,
                217,
                29,
                129,
                113,
                53,
                211,
                114,
                131,
                66,
                131,
                191,
                132,
                38,
                156,
                251,
                49,
                110,
                163,
                218,
                128,
                106,
                72,
                246,
                218,
                167,
                121,
                140,
                254,
                144,
                196,
            ]
        )

        _fixed_info_at_alice = alg.compute_fixed_info(headers, enc.key_size)
        assert _fixed_info_at_alice == bytes(
            [
                0,
                0,
                0,
                7,
                65,
                49,
                50,
                56,
                71,
                67,
                77,
                0,
                0,
                0,
                5,
                65,
                108,
                105,
                99,
                101,
                0,
                0,
                0,
                3,
                66,
                111,
                98,
                0,
                0,
                0,
                128,
            ]
        )

        _dk_at_alice = alg.compute_derived_key(
            _shared_key_at_alice, _fixed_info_at_alice, enc.key_size
        )
        assert _dk_at_alice == bytes(
            [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
        )
        assert urlsafe_b64encode(_dk_at_alice) == b"VqqN6vgjbSBcIijNcacQGg"

        # All-in-one method verification
        dk_at_alice = alg.deliver(
            alice_ephemeral_key, bob_static_pubkey, headers, enc.key_size
        )
        assert dk_at_alice == bytes(
            [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
        )
        assert urlsafe_b64encode(dk_at_alice) == b"VqqN6vgjbSBcIijNcacQGg"

        # Derived key computation at Bob

        # Step-by-step methods verification
        _shared_key_at_bob = bob_static_key.exchange_shared_key(alice_ephemeral_pubkey)
        assert _shared_key_at_bob == _shared_key_at_alice

        _fixed_info_at_bob = alg.compute_fixed_info(headers, enc.key_size)
        assert _fixed_info_at_bob == _fixed_info_at_alice

        _dk_at_bob = alg.compute_derived_key(
            _shared_key_at_bob, _fixed_info_at_bob, enc.key_size
        )
        assert _dk_at_bob == _dk_at_alice

        # All-in-one method verification
        dk_at_bob = alg.deliver(
            bob_static_key, alice_ephemeral_pubkey, headers, enc.key_size
        )
        assert dk_at_bob == dk_at_alice

    def test_ecdh_es_jwe_in_direct_key_agreement_mode(self):
        jwe = JsonWebEncryption()
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }

        for enc in [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ]:
            protected = {"alg": "ECDH-ES", "enc": enc}
            data = jwe.serialize_compact(protected, b"hello", key)
            rv = jwe.deserialize_compact(data, key)
            assert rv["payload"] == b"hello"

    def test_ecdh_es_jwe_json_serialization_single_recipient_in_direct_key_agreement_mode(
        self,
    ):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES", "enc": "A128GCM"}
        header_obj = {"protected": protected}
        data = jwe.serialize_json(header_obj, b"hello", key)
        rv = jwe.deserialize_json(data, key)
        assert rv["payload"] == b"hello"

    def test_ecdh_es_jwe_in_key_agreement_with_key_wrapping_mode(self):
        jwe = JsonWebEncryption()
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }

        for alg in [
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW",
        ]:
            for enc in [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM",
            ]:
                protected = {"alg": alg, "enc": enc}
                data = jwe.serialize_compact(protected, b"hello", key)
                rv = jwe.deserialize_compact(data, key)
                assert rv["payload"] == b"hello"

    def test_ecdh_es_jwe_with_okp_key_in_direct_key_agreement_mode(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        for enc in [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ]:
            protected = {"alg": "ECDH-ES", "enc": enc}
            data = jwe.serialize_compact(protected, b"hello", key)
            rv = jwe.deserialize_compact(data, key)
            assert rv["payload"] == b"hello"

    def test_ecdh_es_jwe_with_okp_key_in_key_agreement_with_key_wrapping_mode(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key("X25519", is_private=True)

        for alg in [
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW",
        ]:
            for enc in [
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
                "A128GCM",
                "A192GCM",
                "A256GCM",
            ]:
                protected = {"alg": alg, "enc": enc}
                data = jwe.serialize_compact(protected, b"hello", key)
                rv = jwe.deserialize_compact(data, key)
                assert rv["payload"] == b"hello"

    def test_ecdh_es_jwe_with_json_serialization_when_kid_is_not_specified(self):
        jwe = JsonWebEncryption()

        bob_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )
        charlie_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )

        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
        }

        unprotected = {"jku": "https://alice.example.com/keys.jwks"}

        recipients = [
            {"header": {"kid": "bob-key-2"}},
            {"header": {"kid": "2021-05-06"}},
        ]

        jwe_aad = b"Authenticate me too."

        header_obj = {
            "protected": protected,
            "unprotected": unprotected,
            "recipients": recipients,
            "aad": jwe_aad,
        }

        payload = b"Three is a magic number."

        data = jwe.serialize_json(header_obj, payload, [bob_key, charlie_key])

        rv_at_bob = jwe.deserialize_json(data, bob_key)

        assert rv_at_bob["header"]["protected"].keys() == protected.keys() | {"epk"}
        assert {
            k: rv_at_bob["header"]["protected"][k]
            for k in rv_at_bob["header"]["protected"].keys() - {"epk"}
        } == protected
        assert rv_at_bob["header"]["unprotected"] == unprotected
        assert rv_at_bob["header"]["recipients"] == recipients
        assert rv_at_bob["header"]["aad"] == jwe_aad
        assert rv_at_bob["payload"] == payload

        rv_at_charlie = jwe.deserialize_json(data, charlie_key)

        assert rv_at_charlie["header"]["protected"].keys() == protected.keys() | {"epk"}
        assert {
            k: rv_at_charlie["header"]["protected"][k]
            for k in rv_at_charlie["header"]["protected"].keys() - {"epk"}
        } == protected
        assert rv_at_charlie["header"]["unprotected"] == unprotected
        assert rv_at_charlie["header"]["recipients"] == recipients
        assert rv_at_charlie["header"]["aad"] == jwe_aad
        assert rv_at_charlie["payload"] == payload

    def test_ecdh_es_jwe_with_json_serialization_when_kid_is_specified(self):
        jwe = JsonWebEncryption()

        bob_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": "bob-key-2",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )
        charlie_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "kid": "2021-05-06",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )

        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
        }

        unprotected = {"jku": "https://alice.example.com/keys.jwks"}

        recipients = [
            {"header": {"kid": "bob-key-2"}},
            {"header": {"kid": "2021-05-06"}},
        ]

        jwe_aad = b"Authenticate me too."

        header_obj = {
            "protected": protected,
            "unprotected": unprotected,
            "recipients": recipients,
            "aad": jwe_aad,
        }

        payload = b"Three is a magic number."

        data = jwe.serialize_json(header_obj, payload, [bob_key, charlie_key])

        rv_at_bob = jwe.deserialize_json(data, bob_key)

        assert rv_at_bob["header"]["protected"].keys() == protected.keys() | {"epk"}
        assert {
            k: rv_at_bob["header"]["protected"][k]
            for k in rv_at_bob["header"]["protected"].keys() - {"epk"}
        } == protected
        assert rv_at_bob["header"]["unprotected"] == unprotected
        assert rv_at_bob["header"]["recipients"] == recipients
        assert rv_at_bob["header"]["aad"] == jwe_aad
        assert rv_at_bob["payload"] == payload

        rv_at_charlie = jwe.deserialize_json(data, charlie_key)

        assert rv_at_charlie["header"]["protected"].keys() == protected.keys() | {"epk"}
        assert {
            k: rv_at_charlie["header"]["protected"][k]
            for k in rv_at_charlie["header"]["protected"].keys() - {"epk"}
        } == protected
        assert rv_at_charlie["header"]["unprotected"] == unprotected
        assert rv_at_charlie["header"]["recipients"] == recipients
        assert rv_at_charlie["header"]["aad"] == jwe_aad
        assert rv_at_charlie["payload"] == payload

    def test_ecdh_es_jwe_with_json_serialization_for_single_recipient(self):
        jwe = JsonWebEncryption()

        key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )

        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i",
        }

        unprotected = {"jku": "https://alice.example.com/keys.jwks"}

        recipients = [{"header": {"kid": "bob-key-2"}}]

        jwe_aad = b"Authenticate me too."

        header_obj = {
            "protected": protected,
            "unprotected": unprotected,
            "recipients": recipients,
            "aad": jwe_aad,
        }

        payload = b"Three is a magic number."

        data = jwe.serialize_json(header_obj, payload, key)

        rv = jwe.deserialize_json(data, key)

        assert rv["header"]["protected"].keys() == protected.keys() | {"epk"}
        assert {
            k: rv["header"]["protected"][k]
            for k in rv["header"]["protected"].keys() - {"epk"}
        } == protected
        assert rv["header"]["unprotected"] == unprotected
        assert rv["header"]["recipients"] == recipients
        assert rv["header"]["aad"] == jwe_aad
        assert rv["payload"] == payload

    def test_ecdh_es_encryption_fails_json_serialization_multiple_recipients_in_direct_key_agreement_mode(
        self,
    ):
        jwe = JsonWebEncryption()
        bob_key = OKPKey.generate_key("X25519", is_private=True)
        charlie_key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-ES", "enc": "A128GCM"}
        header_obj = {"protected": protected}
        with pytest.raises(InvalidAlgorithmForMultipleRecipientsMode):
            jwe.serialize_json(
                header_obj,
                b"hello",
                [bob_key, charlie_key],
            )

    def test_ecdh_es_decryption_with_public_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {"alg": "ECDH-ES", "enc": "A128GCM"}

        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        }
        data = jwe.serialize_compact(protected, b"hello", key)
        with pytest.raises(ValueError):
            jwe.deserialize_compact(data, key)

    def test_ecdh_es_encryption_fails_if_key_curve_is_inappropriate(self):
        jwe = JsonWebEncryption()
        protected = {"alg": "ECDH-ES", "enc": "A128GCM"}

        key = OKPKey.generate_key("Ed25519", is_private=False)
        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", key)

    def test_ecdh_es_decryption_fails_if_key_matches_to_no_recipient(self):
        jwe = JsonWebEncryption()

        bob_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )
        charlie_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )

        protected = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i",
        }

        unprotected = {"jku": "https://alice.example.com/keys.jwks"}

        recipients = [{"header": {"kid": "bob-key-2"}}]

        jwe_aad = b"Authenticate me too."

        header_obj = {
            "protected": protected,
            "unprotected": unprotected,
            "recipients": recipients,
            "aad": jwe_aad,
        }

        payload = b"Three is a magic number."

        data = jwe.serialize_json(header_obj, payload, bob_key)

        with pytest.raises(InvalidUnwrap):
            jwe.deserialize_json(data, charlie_key)

    def test_decryption_with_json_serialization_succeeds_while_encrypted_key_for_another_recipient_is_invalid(
        self,
    ):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.import_key(
            {
                "kid": "Alice's key",
                "kty": "OKP",
                "crv": "X25519",
                "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU",
            }
        )
        OKPKey.import_key(
            {
                "kid": "Bob's key",
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )
        charlie_key = OKPKey.import_key(
            {
                "kid": "Charlie's key",
                "kty": "OKP",
                "crv": "X25519",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )

        data = {
            "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1Ijoi"
            + "UVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9L"
            + "UCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFB"
            + "RnFVQUZhMzlkeUJjIn19",
            "unprotected": {"jku": "https://alice.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"kid": "Bob's key"},
                    "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ"
                    + "eU1cSl55cQ0hGezJu2N9IY0QM",  # Invalid encrypted key
                },
                {
                    "header": {"kid": "Charlie's key"},
                    "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8"
                    + "fe4z3PQ2YH2afvjQ28aiCTWFE",  # Valid encrypted key
                },
            ],
            "iv": "AAECAwQFBgcICQoLDA0ODw",
            "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
            "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ",
        }

        rv_at_charlie = jwe.deserialize_json(data, charlie_key, sender_key=alice_key)

        assert rv_at_charlie.keys() == {"header", "payload"}

        assert rv_at_charlie["header"].keys() == {
            "protected",
            "unprotected",
            "recipients",
        }

        assert rv_at_charlie["header"]["protected"] == {
            "alg": "ECDH-1PU+A128KW",
            "enc": "A256CBC-HS512",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
            "epk": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            },
        }

        assert rv_at_charlie["header"]["unprotected"] == {
            "jku": "https://alice.example.com/keys.jwks"
        }

        assert rv_at_charlie["header"]["recipients"] == [
            {"header": {"kid": "Bob's key"}},
            {"header": {"kid": "Charlie's key"}},
        ]

        assert rv_at_charlie["payload"] == b"Three is a magic number."

    def test_decryption_with_json_serialization_fails_if_encrypted_key_for_this_recipient_is_invalid(
        self,
    ):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.import_key(
            {
                "kid": "Alice's key",
                "kty": "OKP",
                "crv": "X25519",
                "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU",
            }
        )
        bob_key = OKPKey.import_key(
            {
                "kid": "Bob's key",
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )
        OKPKey.import_key(
            {
                "kid": "Charlie's key",
                "kty": "OKP",
                "crv": "X25519",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )

        data = {
            "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1Ijoi"
            + "UVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9L"
            + "UCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFB"
            + "RnFVQUZhMzlkeUJjIn19",
            "unprotected": {"jku": "https://alice.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"kid": "Bob's key"},
                    "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ"
                    + "eU1cSl55cQ0hGezJu2N9IY0QM",  # Invalid encrypted key
                },
                {
                    "header": {"kid": "Charlie's key"},
                    "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8"
                    + "fe4z3PQ2YH2afvjQ28aiCTWFE",  # Valid encrypted key
                },
            ],
            "iv": "AAECAwQFBgcICQoLDA0ODw",
            "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
            "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ",
        }

        with pytest.raises(InvalidUnwrap):
            jwe.deserialize_json(data, bob_key, sender_key=alice_key)

    def test_dir_alg(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(128, is_private=True)
        protected = {"alg": "dir", "enc": "A128GCM"}
        data = jwe.serialize_compact(protected, b"hello", key)
        rv = jwe.deserialize_compact(data, key)
        assert rv["payload"] == b"hello"

        key2 = OctKey.generate_key(256, is_private=True)
        with pytest.raises(ValueError):
            jwe.deserialize_compact(data, key2)

        with pytest.raises(ValueError):
            jwe.serialize_compact(protected, b"hello", key2)

    def test_decryption_of_message_to_multiple_recipients_by_matching_key(self):
        jwe = JsonWebEncryption()

        alice_public_key = OKPKey.import_key(
            {
                "kid": "WjKgJV7VRw3hmgU6--4v15c0Aewbcvat1BsRFTIqa5Q",
                "kty": "OKP",
                "crv": "X25519",
                "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
            }
        )

        key_store = {}

        charlie_X448_key_id = (
            "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw"
        )
        charlie_X448_key = OKPKey.import_key(
            {
                "kid": "_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
                "kty": "OKP",
                "crv": "X448",
                "x": "M-OMugy74ksznVQ-Bp6MC_-GEPSrT8yiAtminJvw0j_UxJtpNHl_hcWMSf_Pfm_ws0vVWvAfwwA",
                "d": "VGZPkclj_7WbRaRMzBqxpzXIpc2xz1d3N1ay36UxdVLfKaP33hABBMpddTRv1f-hRsQUNvmlGOg",
            }
        )
        key_store[charlie_X448_key_id] = charlie_X448_key

        charlie_X25519_key_id = (
            "did:example:123#ZC2jXTO6t4R501bfCXv3RxarZyUbdP2w_psLwMuY6ec"
        )
        charlie_X25519_key = OKPKey.import_key(
            {
                "kid": "ZC2jXTO6t4R501bfCXv3RxarZyUbdP2w_psLwMuY6ec",
                "kty": "OKP",
                "crv": "X25519",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )
        key_store[charlie_X25519_key_id] = charlie_X25519_key

        data = """
            {
                "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
                "unprotected": {
                    "jku": "https://alice.example.com/keys.jwks"
                },
                "recipients": [
                    {
                        "header": {
                            "kid": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
                        },
                        "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
                    },
                    {
                        "header": {
                            "kid": "did:example:123#ZC2jXTO6t4R501bfCXv3RxarZyUbdP2w_psLwMuY6ec"
                        },
                        "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
                    }
                ],
                "iv": "AAECAwQFBgcICQoLDA0ODw",
                "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
                "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
            }"""

        parsed_data = jwe.parse_json(data)

        available_key_id = next(
            recipient["header"]["kid"]
            for recipient in parsed_data["recipients"]
            if recipient["header"]["kid"] in key_store.keys()
        )
        available_key = key_store[available_key_id]

        rv = jwe.deserialize_json(
            parsed_data, (available_key_id, available_key), sender_key=alice_public_key
        )

        assert rv.keys() == {"header", "payload"}

        assert rv["header"].keys() == {"protected", "unprotected", "recipients"}

        assert rv["header"]["protected"] == {
            "alg": "ECDH-1PU+A128KW",
            "enc": "A256CBC-HS512",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
            "epk": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            },
        }

        assert rv["header"]["unprotected"] == {
            "jku": "https://alice.example.com/keys.jwks"
        }

        assert rv["header"]["recipients"] == [
            {
                "header": {
                    "kid": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
                }
            },
            {
                "header": {
                    "kid": "did:example:123#ZC2jXTO6t4R501bfCXv3RxarZyUbdP2w_psLwMuY6ec"
                }
            },
        ]

        assert rv["payload"] == b"Three is a magic number."

    def test_decryption_of_json_string(self):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU",
            }
        )
        bob_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )
        charlie_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE",
                "d": "Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE",
            }
        )

        data = """
            {
                "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
                "unprotected": {
                    "jku": "https://alice.example.com/keys.jwks"
                },
                "recipients": [
                    {
                        "header": {
                            "kid": "bob-key-2"
                        },
                        "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
                    },
                    {
                        "header": {
                            "kid": "2021-05-06"
                        },
                        "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
                    }
                ],
                "iv": "AAECAwQFBgcICQoLDA0ODw",
                "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
                "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
            }"""

        rv_at_bob = jwe.deserialize_json(data, bob_key, sender_key=alice_key)

        assert rv_at_bob.keys() == {"header", "payload"}

        assert rv_at_bob["header"].keys() == {"protected", "unprotected", "recipients"}

        assert rv_at_bob["header"]["protected"] == {
            "alg": "ECDH-1PU+A128KW",
            "enc": "A256CBC-HS512",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
            "epk": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            },
        }

        assert rv_at_bob["header"]["unprotected"] == {
            "jku": "https://alice.example.com/keys.jwks"
        }

        assert rv_at_bob["header"]["recipients"] == [
            {"header": {"kid": "bob-key-2"}},
            {"header": {"kid": "2021-05-06"}},
        ]

        assert rv_at_bob["payload"] == b"Three is a magic number."

        rv_at_charlie = jwe.deserialize_json(data, charlie_key, sender_key=alice_key)

        assert rv_at_charlie.keys() == {"header", "payload"}

        assert rv_at_charlie["header"].keys() == {
            "protected",
            "unprotected",
            "recipients",
        }

        assert rv_at_charlie["header"]["protected"] == {
            "alg": "ECDH-1PU+A128KW",
            "enc": "A256CBC-HS512",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
            "epk": {
                "kty": "OKP",
                "crv": "X25519",
                "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            },
        }

        assert rv_at_charlie["header"]["unprotected"] == {
            "jku": "https://alice.example.com/keys.jwks"
        }

        assert rv_at_charlie["header"]["recipients"] == [
            {"header": {"kid": "bob-key-2"}},
            {"header": {"kid": "2021-05-06"}},
        ]

        assert rv_at_charlie["payload"] == b"Three is a magic number."

    def test_parse_json(self):
        json_msg = """
            {
                "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
                "unprotected": {
                    "jku": "https://alice.example.com/keys.jwks"
                },
                "recipients": [
                    {
                        "header": {
                            "kid": "bob-key-2"
                        },
                        "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
                    },
                    {
                        "header": {
                            "kid": "2021-05-06"
                        },
                        "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
                    }
                ],
                "iv": "AAECAwQFBgcICQoLDA0ODw",
                "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
                "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
            }"""

        parsed_msg = JsonWebEncryption.parse_json(json_msg)

        assert parsed_msg == {
            "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
            "unprotected": {"jku": "https://alice.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"kid": "bob-key-2"},
                    "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN",
                },
                {
                    "header": {"kid": "2021-05-06"},
                    "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE",
                },
            ],
            "iv": "AAECAwQFBgcICQoLDA0ODw",
            "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
            "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ",
        }

    def test_parse_json_fails_if_json_msg_is_invalid(self):
        json_msg = """
            {
                "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19",
                "unprotected": {
                    "jku": "https://alice.example.com/keys.jwks"
                },
                "recipients": [
                    {
                        "header": {
                            "kid": "bob-key-2"
                        ,
                        "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
                    },
                    {
                        "header": {
                            "kid": "2021-05-06"
                        },
                        "encrypted_key": "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
                    }
                ],
                "iv": "AAECAwQFBgcICQoLDA0ODw",
                "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
                "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
            }"""

        with pytest.raises(DecodeError):
            JsonWebEncryption.parse_json(json_msg)

    def test_decryption_fails_if_ciphertext_is_invalid(self):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU",
            }
        )
        bob_key = OKPKey.import_key(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg",
            }
        )

        data = {
            "protected": "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1Ijoi"
            + "UVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9L"
            + "UCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFB"
            + "RnFVQUZhMzlkeUJjIn19",
            "unprotected": {"jku": "https://alice.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"kid": "bob-key-2"},
                    "encrypted_key": "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ"
                    + "eU1cSl55cQ0hGezJu2N9IY0QN",
                }
            ],
            "iv": "AAECAwQFBgcICQoLDA0ODw",
            "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFY",  # invalid ciphertext
            "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ",
        }

        with pytest.raises(InvalidTag):
            jwe.deserialize_json(data, bob_key, sender_key=alice_key)

    def test_generic_serialize_deserialize_for_compact_serialization(self):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.generate_key("X25519", is_private=True)
        bob_key = OKPKey.generate_key("X25519", is_private=True)

        header_obj = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256"}

        data = jwe.serialize(header_obj, b"hello", bob_key, sender_key=alice_key)
        assert isinstance(data, bytes)

        rv = jwe.deserialize(data, bob_key, sender_key=alice_key)
        assert rv["payload"] == b"hello"

    def test_generic_serialize_deserialize_for_json_serialization(self):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.generate_key("X25519", is_private=True)
        bob_key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256"}
        header_obj = {"protected": protected}

        data = jwe.serialize(header_obj, b"hello", bob_key, sender_key=alice_key)
        assert isinstance(data, dict)

        rv = jwe.deserialize(data, bob_key, sender_key=alice_key)
        assert rv["payload"] == b"hello"

    def test_generic_deserialize_for_json_serialization_string(self):
        jwe = JsonWebEncryption()

        alice_key = OKPKey.generate_key("X25519", is_private=True)
        bob_key = OKPKey.generate_key("X25519", is_private=True)

        protected = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256"}
        header_obj = {"protected": protected}

        data = jwe.serialize(header_obj, b"hello", bob_key, sender_key=alice_key)
        assert isinstance(data, dict)

        data_as_string = json.dumps(data)

        rv = jwe.deserialize(data_as_string, bob_key, sender_key=alice_key)
        assert rv["payload"] == b"hello"
