import json
import time
from typing import Any

from authlib.common.security import generate_token
from authlib.jose import JsonWebKey, JsonWebSignature, jwt
from authlib.jose.errors import UnsupportedAlgorithmError
from authlib.jose.rfc7517 import AsymmetricKey
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc9449.nonce import DPoPNonceCache, DefaultDPoPNonceCache
from authlib.oauth2.rfc9449.validator import normalize_url


def sign_dpop_proof(
        jwk,
        alg,
        method,
        url,
        nonce=None,
        access_token=None,
        claims=None,
        headers=None,
        expires_in=30,
):
    """
    Generate the DPoP proof JWT

    :param jwk: the JWK keypair used to sign this proof
    :param alg: the algorithm used
    :param method: the HTTP method of the request this proof is being attached to
    :param url: the HTTP url of the endpoint this proof is being attached to
    :param nonce: an optional nonce is one has been provided by the server
    :param access_token: an optional access token when requesting a protected resource
    :param claims: optional additional payload claims to include
    :param headers: optional additional header claims to include
    :param expires_in: optional expiration time, defaults to 30 seconds
    :return:
    .. _`Section 4.3`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
    """
    header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": json.loads(jwk.as_json(is_private=False)),
    }

    if headers:
        header.update(headers)

    url = normalize_url(url)

    now = time.time()
    payload = {
        "jti": generate_token(36),
        "htm": method,
        "htu": url,
        "iat": int(now),
    }

    if expires_in:
        payload["exp"] = now + expires_in

    if access_token:
        payload["ath"] = create_s256_code_challenge(access_token)

    if nonce:
        payload["nonce"] = nonce

    if claims:
        payload.update(claims)

    return jwt.encode(header, payload, jwk).decode("utf-8")


class DPoPProof:
    DEFAULT_ALGORITHM = "ES256"

    def __init__(
            self,
            jwk=None,
            claims=None,
            headers=None,
            preferred_alg=DEFAULT_ALGORITHM,
            jwk_options=None,
            nonce_cache: DPoPNonceCache = DefaultDPoPNonceCache()):
        """
        Initialize the DPoPProof signing with prepopulated values.

        :param jwk: the JWK keypair used to sign this proof
        :param claims: optional additional payload claims to include
        :param headers: optional additional header claims to include
        :param preferred_alg: the preferred algorithm to use when creating the JWK, defaults to ES256
        :param jwk_options: additional options to provide when creating the JWK
        :param nonce_cache: a custom DPoPNonceCache to use, defaults to DefaultDPoPNonceCache
        """
        self.claims = claims
        self.headers = headers
        self.preferred_alg = preferred_alg
        self.jwk = jwk
        self.alg = None
        if jwk:
            self.alg = self._get_alg_from_jwk(jwk)
        self.jwk_options = jwk_options
        self.nonce_cache = nonce_cache

    def set_nonce(self, origin: str, nonce: str):
        origin = normalize_url(origin)
        self.nonce_cache[origin] = nonce

    def generate_jwk(self, token, supported_algs: list[str]):
        """
        Create a new JWK keypair if one isn't provided on the initial token
        :param token: the initial token if provided during Client initialization
        :param supported_algs: the list of algorithms that the server supports
        :return: the JWK keypair
        """
        token = OAuth2Token.from_dict(token)
        if not self.jwk:
            if token and "dpop_jwk" in token:
                self.alg = self._get_alg_from_jwk(token["dpop_jwk"])
                self.jwk = JsonWebKey.import_key(token["dpop_jwk"])
            elif self.jwk is None:
                self.alg = self._negotiate_algorithm(supported_algs)
                self.jwk = JsonWebKey.generate_key_from_jws_alg(self.alg, self.jwk_options, True)

    def prepare(self, method, uri, headers, body, nonce_origin=None, token=None):
        nonce = self.nonce_cache[nonce_origin]
        access_token = None
        if token:
            access_token = token["access_token"]
        proof = sign_dpop_proof(self.jwk,
                                self.alg,
                                method,
                                uri,
                                nonce=nonce,
                                access_token=access_token,
                                claims=self.claims,
                                headers=self.headers)
        headers = headers or {}
        headers["DPoP"] = f"{proof}"
        return uri, headers, body

    def get_jwk_as_dict(self):
        return self.jwk.as_dict(is_private=True, alg=self.alg)

    def _negotiate_algorithm(self, supported_algs: list[str]):
        if not supported_algs:
            return self.preferred_alg

        if self.preferred_alg in supported_algs:
            supported_algs.pop(supported_algs.index(self.preferred_alg))
            supported_algs.insert(0, self.preferred_alg)

        for alg in supported_algs:
            algorithm = JsonWebSignature.get_algorithm(alg)
            if not issubclass(algorithm.key_cls, AsymmetricKey):
                # Only Asymmetric algorithms are allowed by RFC-9449
                continue
            return alg
        raise UnsupportedAlgorithmError()

    def _get_alg_from_jwk(self, jwk: dict[str, Any]):
        if "alg" in jwk:
            return jwk["alg"]
        else:
            return self.preferred_alg
