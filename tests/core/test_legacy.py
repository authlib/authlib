from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib._joserfc_helpers import import_any_key
from authlib.jose import OctKey as AuthlibOctKey


def test_import_legacy_oct_key():
    key1 = AuthlibOctKey.generate_key()
    key2 = import_any_key(key1)
    assert isinstance(key2, OctKey)


def test_import_from_json_str():
    data = '{"kty":"oct","k":"mGF6N2AY9YSRizMBv-DMe5NGpIP7AAcGX_w_jdiHMWc"}'
    key = import_any_key(data)
    assert isinstance(key, OctKey)


def test_import_raw_str():
    key = import_any_key("foo")
    assert isinstance(key, OctKey)


def test_import_key_set():
    data = {
        "keys": [{"kty": "oct", "k": "mGF6N2AY9YSRizMBv-DMe5NGpIP7AAcGX_w_jdiHMWc"}]
    }
    key = import_any_key(data)
    assert isinstance(key, KeySet)
