import importlib
import json

from fastapi.responses import Response

from authlib.common.security import generate_token
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6750 import BearerTokenGenerator

from .requests import create_json_request as _create_json_request
from .requests import create_oauth2_request as _create_oauth2_request
from .signals import client_authenticated
from .signals import token_revoked


class AuthorizationServer(_AuthorizationServer):
    """FastAPI implementation of Authlib AuthorizationServer."""

    def __init__(self, config=None, query_client=None, save_token=None):
        super().__init__()
        self._query_client = query_client
        self._save_token = save_token
        self._error_uris = None

        if config is not None:
            self.load_config(config)

    def init_app(self, config, query_client=None, save_token=None):
        if query_client is not None:
            self._query_client = query_client

        if save_token is not None:
            self._save_token = save_token

        self.load_config(config)

    def load_config(self, config):
        self.register_token_generator(
            "default", self.create_bearer_token_generator(config)
        )
        self.scopes_supported = config.get("OAUTH2_SCOPES_SUPPORTED")
        self._error_uris = config.get("OAUTH2_ERROR_URIS")

    def query_client(self, client_id):
        return self._query_client(client_id)

    def save_token(self, token, request):
        return self._save_token(token, request)

    def get_error_uri(self, request, error):
        if self._error_uris:
            return dict(self._error_uris).get(error.error)

    async def _create_oauth2_request(self, request):
        if isinstance(request, OAuth2Request):
            return request
        return await _create_oauth2_request(request)

    async def _create_json_request(self, request):
        if isinstance(request, OAuth2Request):
            return request
        return await _create_json_request(request)

    async def _parse_request(self, request):
        content_type = request.headers.get("content-type", "")

        if "application/json" in content_type:
            return await self._create_json_request(request)

        return await self._create_oauth2_request(request)

    async def create_authorization_response(self, request=None, grant_user=None):
        if request is None:
            raise TypeError(
                "create_authorization_response() requires the FastAPI/Starlette "
                "request, since FastAPI has no global request proxy"
            )

        if not isinstance(request, OAuth2Request):
            request = await self._parse_request(request)

        return super().create_authorization_response(request, grant_user=grant_user)

    async def create_token_response(self, request=None):
        if request is None:
            raise TypeError(
                "create_token_response() requires the FastAPI/Starlette "
                "request, since FastAPI has no global request proxy"
            )

        if not isinstance(request, OAuth2Request):
            request = await self._parse_request(request)

        return super().create_token_response(request)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)

        if isinstance(headers, list):
            headers = {k: v for k, v in headers}

        return Response(
            payload,
            status_code=status_code,
            headers=headers,
        )

    def send_signal(self, name, *args, **kwargs):
        if name == "after_authenticate_client":
            client_authenticated.send(self, *args, **kwargs)
        elif name == "after_revoke_token":
            token_revoked.send(self, *args, **kwargs)

    def create_bearer_token_generator(self, config):
        conf = config.get("OAUTH2_ACCESS_TOKEN_GENERATOR", True)
        access_token_generator = create_token_generator(conf, 42)

        conf = config.get("OAUTH2_REFRESH_TOKEN_GENERATOR", False)
        refresh_token_generator = create_token_generator(conf, 48)

        expires_conf = config.get("OAUTH2_TOKEN_EXPIRES_IN")
        expires_generator = create_token_expires_in_generator(expires_conf)

        return BearerTokenGenerator(
            access_token_generator,
            refresh_token_generator,
            expires_generator,
        )

    def create_oauth2_request(self, request):
        if isinstance(request, OAuth2Request):
            return request
        raise TypeError(
            "Expected an OAuth2Request. "
            "Use create_token_response() or create_authorization_response() "
            "with a FastAPI/Starlette Request."
        )

    def create_json_request(self, request):
        if isinstance(request, OAuth2Request):
            return request
        raise TypeError(
            "Expected an OAuth2Request.Use the asynchronous request parsing methods."
        )


def import_string(import_name):
    """Import an object from a module, e.g. ``"package.module.attribute"``
    or ``"package.module:attribute"``."""
    if not isinstance(import_name, str):
        return import_name
    import_name = import_name.replace(":", ".")
    module_name, _, obj_name = import_name.rpartition(".")
    if not module_name:
        raise ImportError(
            f"Invalid import string {import_name!r}, expected "
            f"'package.module.attribute' format"
        )
    module = importlib.import_module(module_name)
    try:
        return getattr(module, obj_name)
    except AttributeError as exc:
        raise ImportError(
            f"Cannot import {obj_name!r} from module {module_name!r}"
        ) from exc


def create_token_expires_in_generator(expires_in_conf=None):
    if isinstance(expires_in_conf, str):
        return import_string(expires_in_conf)

    data = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if isinstance(expires_in_conf, dict):
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:

        def token_generator(*args, **kwargs):
            return generate_token(length)

        return token_generator
