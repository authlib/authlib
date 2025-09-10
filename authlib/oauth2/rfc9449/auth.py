from typing import Any

from authlib.oauth2.auth import AuthProtocol
from authlib.oauth2.rfc9449 import DPoPProof


def is_auth_server_dpop_error(response) -> bool:
    if response.status_code == 400:
        body = response.json()
        if "error" in body and body["error"] == "use_dpop_nonce":
            return True
    return False


def is_resource_server_dpop_error(response) -> bool:
    return response.status_code == 401 and "use_dpop_nonce" in response.headers.get("www-authenticate", "")


class DPoPAuth(AuthProtocol):
    def __init__(self, dpop_proof: DPoPProof):
        self.dpop_proof = dpop_proof

    def prepare(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        access_token = None
        if "Authorization" in headers:
            _, access_token = headers["Authorization"].split()
        return self.dpop_proof.prepare(
            method,
            uri,
            headers,
            body,
            nonce_origin=uri,
            access_token=access_token)

    def prepare_retry(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        return self.prepare(method, uri, headers, body)

    def should_retry(self, response) -> bool:
        if "DPoP-Nonce" in response.headers:
            self.dpop_proof.set_nonce(str(response.url), response.headers["DPoP-Nonce"])

        return is_resource_server_dpop_error(response) or is_auth_server_dpop_error(response)
