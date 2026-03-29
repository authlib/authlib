import pytest

from authlib.jose.rfc7518.ec_key import ECKey
from authlib.jose.rfc7518.oct_key import OctKey
from authlib.jose.rfc7518.rsa_key import RSAKey
from authlib.jose.rfc8037.okp_key import OKPKey
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants.util import generate_id_token

hmac_key = OctKey.generate_key(256)
rsa_key = RSAKey.generate_key(2048, is_private=True)
ec_key = ECKey.generate_key("P-256", is_private=True)
okp_key = OKPKey.generate_key("Ed25519", is_private=True)
ec_secp256k1_key = ECKey.generate_key("secp256k1", is_private=True)


@pytest.mark.parametrize(
    "alg,key",
    [
        ("none", None),
        ("HS256", hmac_key),
        ("HS384", hmac_key),
        ("HS512", hmac_key),
        ("RS256", rsa_key),
        ("RS384", rsa_key),
        ("RS512", rsa_key),
        ("ES256", ec_key),
        ("PS256", rsa_key),
        ("PS384", rsa_key),
        ("PS512", rsa_key),
        ("EdDSA", okp_key),
        ("ES256K", ec_secp256k1_key),
    ],
)
def test_generate_id_token(alg, key):
    token = {"access_token": "test_token"}
    user_info = UserInfo({"sub": "123"})

    result = generate_id_token(
        token=token,
        user_info=user_info,
        key=key,
        iss="https://provider.test",
        aud="client_id",
        alg=alg,
    )
    assert result is not None
