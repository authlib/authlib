import json
import time
import traceback
from enum import Enum

from authlib.common.security import generate_token
from authlib.jose import JsonWebKey, jwt
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc7636 import create_s256_code_challenge


def generate_ec_p256_jwk(options=None):
    return JsonWebKey.generate_key("EC", "P-256", options=options, is_private=True)


# Key could come from a provided token as a string
# or internally, so should pass it as a string
# Header:
#   typ: dpop+jwt
#   alg: <alg>
#   jwk: <jwk public key>
# Payload:
#   jti: generate_token()
#   htm: method
#   htu: url
#   iat: time.time()
#   ath: <token> # Optional
#   nonce: <nonce> # Optional
def sign_dpop_proof(
        jwk,
        alg,
        method,
        url,
        nonce=None,
        token=None,
        claims=None,
        headers=None,
        expires_in=30,
):
    header = {
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": json.loads(jwk.as_json(is_private=False)),
    }

    if headers:
        header.update(headers)

    now = time.time()
    payload = {
        "jti": generate_token(36),
        "htm": method,
        "htu": url,
        "iat": int(now),
    }

    if expires_in:
        payload["exp"] = now + expires_in

    if token:
        payload["ath"] = create_s256_code_challenge(token["access_token"])

    if nonce:
        payload["nonce"] = nonce

    if claims:
        payload.update(claims)

    return jwt.encode(header, payload, jwk).decode("utf-8")


class DPoPProof:
    name = "dpop_proof"
    DEFAULT_ALGORITHM = "ES256"
    DEFAULT_JWK_GENERATOR = generate_ec_p256_jwk

    class NonceKey(Enum):
        AUTH_SERVER_NONCE_KEY = "auth_server"
        RESOURCE_SERVER_NONCE_KEY = "resource_server"

    def __init__(
            self,
            jwk=None,
            claims=None,
            headers=None,
            alg=DEFAULT_ALGORITHM,
            jwk_generator=DEFAULT_JWK_GENERATOR,
            jwk_generator_options=None,
            update_nonces=None,
            auth_server_nonce=None,
            resource_server_nonce=None):
        self.claims = claims
        self.headers = headers
        self.alg = alg
        self.jwk = jwk

        if not callable(jwk_generator):
            raise ValueError("jwk_generator is not a callable function")
        self.jwk_generator = jwk_generator
        self.jwk_generator_options = jwk_generator_options

        if update_nonces and not callable(update_nonces):
            raise ValueError("update_nonces is not a callable function")
        self.update_nonces = update_nonces

        self.nonces = {
            self.NonceKey.AUTH_SERVER_NONCE_KEY: auth_server_nonce,
            self.NonceKey.RESOURCE_SERVER_NONCE_KEY: resource_server_nonce
        }
        self.token = None

    def set_nonce(self, key: NonceKey, nonce):
        if key not in self.NonceKey:
            return

        cur_nonce = None
        if key in self.nonces:
            cur_nonce = self.nonces[key]

        self.nonces[key] = nonce

        if cur_nonce != nonce and key is self.NonceKey.RESOURCE_SERVER_NONCE_KEY:
            # AUTH_SERVER_NONCE_KEY is already emitted via update_token
            self._emit_nonces()

    def generate_jwk(self, token):
        self.set_token(token)
        if not self.jwk:
            if self.token and "dpop_jwk" in self.token:
                self.jwk = JsonWebKey.import_key(self.token["dpop_jwk"])
            elif self.jwk is None:
                self.jwk = self.jwk_generator(self.jwk_generator_options)

    def set_token(self, token):
        self.token = OAuth2Token.from_dict(token)

    def prepare(self, method, uri, headers, body, nonce_key: NonceKey = None, token=None):
        nonce = None
        if nonce_key and nonce_key in self.nonces:
            nonce = self.nonces[nonce_key]

        proof = sign_dpop_proof(self.jwk,
                                self.alg,
                                method,
                                uri,
                                nonce=nonce,
                                token=token,
                                claims=self.claims,
                                headers=self.headers)
        headers = headers or {}
        headers["DPoP"] = f"{proof}"
        return uri, headers, body

    def _emit_nonces(self):
        if self.token and self.update_nonces:
            self.update_nonces(self.token, self.nonces)