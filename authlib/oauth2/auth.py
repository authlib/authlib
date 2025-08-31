import base64
from typing import Any, Callable, Protocol

from authlib.common.encoding import to_bytes, to_native
from authlib.common.urls import add_params_to_qs, add_params_to_uri
from .rfc6749 import OAuth2Token
from .rfc6750 import add_bearer_token
from .rfc9449 import add_dpop_token


def encode_client_secret_basic(client, method, uri, headers, body):
    text = f"{client.client_id}:{client.client_secret}"
    auth = to_native(base64.b64encode(to_bytes(text, "latin1")))
    headers["Authorization"] = f"Basic {auth}"
    return uri, headers, body


def encode_client_secret_post(client, method, uri, headers, body):
    body = add_params_to_qs(
        body or "",
        [
            ("client_id", client.client_id),
            ("client_secret", client.client_secret or ""),
        ],
    )
    if "Content-Length" in headers:
        headers["Content-Length"] = str(len(body))
    return uri, headers, body


def encode_none(client, method, uri, headers, body):
    if method == "GET":
        uri = add_params_to_uri(uri, [("client_id", client.client_id)])
        return uri, headers, body
    body = add_params_to_qs(body, [("client_id", client.client_id)])
    if "Content-Length" in headers:
        headers["Content-Length"] = str(len(body))
    return uri, headers, body


class AuthProtocol(Protocol):
    def prepare(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        ...


def is_auth_server_dpop_error(response):
    if response.status_code == 400:
        body = response.json()
        if "error" in body and body["error"] == "use_dpop_nonce":
            return True
    return False


def is_resource_server_dpop_error(response):
    return response.status_code == 401 and "use_dpop_nonce" in response.headers.get("www-authenticate", "")


class DPoPAuthProtocol(Protocol):
    def set_dpop_nonce(self, origin, nonce):
        ...

    def dpop_prepare(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        ...

    def is_dpop_error(self, response) -> Callable:
        ...


class DPoPAuthMixin(DPoPAuthProtocol):
    def __init__(self, dpop_error_validator, dpop_proof=None):
        self.nonce = None
        if not callable(dpop_error_validator):
            raise ValueError("dpop_error_validator is not a callable function")
        self.dpop_error_validator = dpop_error_validator
        self.dpop_proof = dpop_proof

    def set_dpop_nonce(self, origin: str, nonce: str):
        self.dpop_proof.set_nonce(origin, nonce)

    def dpop_prepare(self, method, uri, headers, body):
        if self.dpop_proof:
            token = getattr(self, "token", None)
            uri, headers, body = self.dpop_proof.prepare(
                method,
                uri,
                headers,
                body,
                nonce_origin=uri,
                token=token)
        return uri, headers, body

    def is_dpop_error(self, response):
        if "DPoP-Nonce" in response.headers:
            self.set_dpop_nonce(str(response.url), response.headers.get("DPoP-Nonce"))

        return self.dpop_error_validator(response)


class ClientAuth(DPoPAuthMixin, AuthProtocol):
    """Attaches OAuth Client Information to HTTP requests.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param auth_method: Client auth method for token endpoint. The supported
        methods for now:

        * client_secret_basic (default)
        * client_secret_post
        * none
    """
    DEFAULT_AUTH_METHODS = {
        "client_secret_basic": encode_client_secret_basic,
        "client_secret_post": encode_client_secret_post,
        "none": encode_none,
    }

    def __init__(self, client_id, client_secret, auth_method=None, dpop_proof=None):
        if auth_method is None:
            auth_method = "client_secret_basic"

        self.client_id = client_id
        self.client_secret = client_secret

        if auth_method in self.DEFAULT_AUTH_METHODS:
            auth_method = self.DEFAULT_AUTH_METHODS[auth_method]

        self.auth_method = auth_method
        super().__init__(is_auth_server_dpop_error, dpop_proof=dpop_proof)

    def prepare(self, method, uri, headers, body):
        uri, headers, body = self.auth_method(self, method, uri, headers, body)
        return self.dpop_prepare(method, uri, headers, body)


class TokenAuth(DPoPAuthMixin, AuthProtocol):
    """Attach token information to HTTP requests.

    :param token: A dict or OAuth2Token instance of an OAuth 2.0 token
    :param token_placement: The placement of the token, default is ``header``,
        available choices:

        * header (default)
        * body
        * uri
    """
    DEFAULT_TOKEN_TYPE = "bearer"
    SIGN_METHODS = {"bearer": add_bearer_token, "dpop": add_dpop_token}

    def __init__(self, token, token_placement="header", client=None, dpop_proof=None):
        self.token = OAuth2Token.from_dict(token)
        self.token_placement = token_placement
        self.client = client
        self.hooks = set()
        super().__init__(is_resource_server_dpop_error, dpop_proof=dpop_proof)

    def set_token(self, token):
        self.token = OAuth2Token.from_dict(token)

    def prepare(self, method, uri, headers, body):
        token_type = self.token.get("token_type", self.DEFAULT_TOKEN_TYPE)
        sign = self.SIGN_METHODS[token_type.lower()]
        uri, headers, body = sign(
            self.token["access_token"], uri, headers, body, self.token_placement
        )

        if token_type.lower() == "dpop":
            uri, headers, body = self.dpop_prepare(method, uri, headers, body)

        for hook in self.hooks:
            uri, headers, body = hook(uri, headers, body)

        return uri, headers, body

    def __del__(self):
        del self.client
        del self.hooks
