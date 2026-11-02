import importlib
import warnings

import pytest
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey

from authlib._joserfc_helpers import import_any_key
from authlib.deprecate import AuthlibDeprecationWarning
from tests.util import HMAC_SECRET

with warnings.catch_warnings():
    warnings.simplefilter("ignore", AuthlibDeprecationWarning)
    import authlib.jose
    from authlib.jose import OctKey as AuthlibOctKey


def test_authlib_jose_module_is_deprecated():
    with pytest.warns(AuthlibDeprecationWarning, match="authlib.jose module"):
        importlib.reload(authlib.jose)


def test_import_legacy_oct_key():
    key1 = AuthlibOctKey.generate_key()
    with pytest.warns(AuthlibDeprecationWarning, match="Please use joserfc"):
        key2 = import_any_key(key1)
    assert isinstance(key2, OctKey)


def test_import_from_json_str():
    data = '{"kty":"oct","k":"mGF6N2AY9YSRizMBv-DMe5NGpIP7AAcGX_w_jdiHMWc"}'
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        key = import_any_key(data)
    assert isinstance(key, OctKey)


@pytest.mark.filterwarnings(
    "ignore:Using implicit key type:joserfc.errors.SecurityWarning"
)
def test_import_raw_str():
    with pytest.warns(AuthlibDeprecationWarning, match="Please use OctKey"):
        key = import_any_key(HMAC_SECRET)
    assert isinstance(key, OctKey)


def test_import_key_set():
    data = {
        "keys": [{"kty": "oct", "k": "mGF6N2AY9YSRizMBv-DMe5NGpIP7AAcGX_w_jdiHMWc"}]
    }
    with pytest.warns(AuthlibDeprecationWarning, match="KeySet.import_key_set"):
        key = import_any_key(data)
    assert isinstance(key, KeySet)
