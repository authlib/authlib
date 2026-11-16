import hashlib

from authlib.common.encoding import to_bytes
from authlib.common.encoding import urlsafe_b64encode

_HASH_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
    "RS256": hashlib.sha256,
    "RS384": hashlib.sha384,
    "RS512": hashlib.sha512,
    "PS256": hashlib.sha256,
    "PS384": hashlib.sha384,
    "PS512": hashlib.sha512,
    "ES256": hashlib.sha256,
    "ES256K": hashlib.sha256,
    "ES384": hashlib.sha384,
    "ES512": hashlib.sha512,
    # RFC 8032 §5.1: Ed25519 uses SHA-512.
    "EdDSA": hashlib.sha512,
    "Ed25519": hashlib.sha512,
}


def create_half_hash(s, alg):
    """Return the ``at_hash`` or ``c_hash`` value of a string.

    Per OpenID Connect Core §3.1.3.6, the hash algorithm is the one used by
    the ``alg`` of the ID Token.

    :param s: the access token or the authorization code
    :param alg: the ``alg`` of the ID Token
    :return: the base64url encoded left half of the hash, or ``None`` if
        the ``alg`` has no known hash algorithm
    """
    hash_alg = _HASH_ALGORITHMS.get(alg)
    if hash_alg is None:
        return None

    data_digest = hash_alg(to_bytes(s)).digest()
    slice_index = int(len(data_digest) / 2)
    return urlsafe_b64encode(data_digest[:slice_index])
