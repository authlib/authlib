import base64
from typing import Any
from typing import Protocol

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_native
from authlib.common.urls import add_params_to_qs
from authlib.common.urls import add_params_to_uri
from .rfc6749 import OAuth2Token
from .rfc6749 import UnsupportedTokenTypeError
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

    def prepare_retry(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        return uri, headers, body

    def should_retry(self, response) -> bool:
        return False


def create_auth(*auths: AuthProtocol):
    auths = tuple(auth for auth in auths if auth is not None)
    if len(auths) == 1:
        return auths[0]
    return CompositeAuth(*auths)


class ClientAuth(AuthProtocol):
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

    def __init__(self, client_id, client_secret, auth_method=None):
        if auth_method is None:
            auth_method = "client_secret_basic"

        self.client_id = client_id
        self.client_secret = client_secret

        if auth_method in self.DEFAULT_AUTH_METHODS:
            auth_method = self.DEFAULT_AUTH_METHODS[auth_method]

        self.auth_method = auth_method

    def prepare(self, method, uri, headers, body):
        return self.auth_method(self, method, uri, headers, body)


class TokenAuth(AuthProtocol):
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

    def __init__(self, token, token_placement="header", client=None):
        self.token = OAuth2Token.from_dict(token)
        self.token_placement = token_placement
        self.hooks = set()
        self.client = client

    def set_token(self, token):
        self.token = OAuth2Token.from_dict(token)

    def prepare(self, method, uri, headers, body):
        token_type = self.token.get("token_type", self.DEFAULT_TOKEN_TYPE).lower()
        try:
            sign = self.SIGN_METHODS[token_type]
        except KeyError as error:
            description = f"Unsupported token_type: {str(error)}"
            raise UnsupportedTokenTypeError(description=description) from error

        uri, headers, body = sign(
            self.token["access_token"], uri, headers, body, self.token_placement
        )

        for hook in self.hooks:
            argcount = hook.__code__.co_argcount
            if argcount == 4:
                uri, headers, body = hook(method, uri, headers, body)
            else:
                uri, headers, body = hook(uri, headers, body)

        return uri, headers, body

    def __del__(self):
        del self.client
        del self.hooks


class CompositeAuth(AuthProtocol):
    def __init__(self, *auths: AuthProtocol):
        self.auths = auths

    def prepare(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        for auth in self.auths:
            uri, headers, body = auth.prepare(method, uri, headers, body)
        return uri, headers, body

    def prepare_retry(self, method, uri, headers, body) -> tuple[Any, Any, Any]:
        for auth in self.auths:
            uri, headers, body = auth.prepare_retry(method, uri, headers, body)
        return uri, headers, body

    def should_retry(self, response) -> bool:
        for auth in self.auths:
            if auth.should_retry(response):
                return True
        return False

