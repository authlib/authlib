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
    """FastAPI implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
    Initialize it with ``query_client``, ``save_token`` methods and a
    configuration dict, which is the FastAPI equivalent of Flask's
    ``app.config``::

        def query_client(client_id):
            return Client.query.filter_by(client_id=client_id).first()


        def save_token(token, request):
            if request.user:
                user_id = request.user.id
            else:
                user_id = None

            client = request.client
            tok = Token(client_id=client.client_id, user_id=user_id, **token)
            db.session.add(tok)
            db.session.commit()


        server = AuthorizationServer(OAUTH2_CONFIG, query_client, save_token)
        # or initialize lazily
        server = AuthorizationServer()
        server.init_app(OAUTH2_CONFIG, query_client, save_token)

    Since FastAPI has no global request proxy, the Starlette request must be
    passed to the OAuth2 endpoints::

        @app.post("/oauth/token")
        async def issue_token(request: Request):
            return await server.create_token_response(request)


        @app.get("/oauth/authorize")
        async def authorize(request: Request):
            # resolve the current user first
            return await server.create_authorization_response(request, grant_user=user)
    """

    def __init__(self, config=None, query_client=None, save_token=None):
        super().__init__()
        self._query_client = query_client
        self._save_token = save_token
        self._error_uris = None
        if config is not None:
            self.load_config(config)

    def init_app(self, config, query_client=None, save_token=None):
        """Initialize later with a configuration dict."""
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
            uris = dict(self._error_uris)
            return uris.get(error.error)

    async def create_oauth2_request(self, request):
        """Create a :class:`.FastApiOAuth2Request` from a FastAPI/Starlette
        request. An already parsed request is returned unchanged."""
        if isinstance(request, OAuth2Request):
            return request
        return await _create_oauth2_request(request)

    async def create_json_request(self, request):
        """Create a :class:`.FastApiJsonRequest` from a FastAPI/Starlette
        request. An already parsed request is returned unchanged."""
        if isinstance(request, OAuth2Request):
            return request
        return await _create_json_request(request)

    async def _parse_request(self, request):
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            return await self.create_json_request(request)
        return await self.create_oauth2_request(request)

    async def create_authorization_response(self, request=None, grant_user=None):
        """Validate authorization request and create authorization response.

        :param request: FastAPI/Starlette request instance
        :param grant_user: current authorized user
        :return: Response instance
        """
        if request is None:
            raise TypeError(
                "create_authorization_response() requires the FastAPI/Starlette "
                "request, since FastAPI has no global request proxy"
            )
        if not isinstance(request, OAuth2Request):
            request = await self._parse_request(request)
        return super().create_authorization_response(request, grant_user=grant_user)

    async def create_token_response(self, request=None):
        """Validate token request and create token response.

        :param request: FastAPI/Starlette request instance
        :return: Response instance
        """
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
        return Response(payload, status_code=status_code, headers=headers)

    def send_signal(self, name, *args, **kwargs):
        if name == "after_authenticate_client":
            client_authenticated.send(self, *args, **kwargs)
        elif name == "after_revoke_token":
            token_revoked.send(self, *args, **kwargs)

    def create_bearer_token_generator(self, config):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.oauth2.rfc6750.BearerToken`.

        Configurable settings:

        1. OAUTH2_ACCESS_TOKEN_GENERATOR: Boolean or import string, default is True.
        2. OAUTH2_REFRESH_TOKEN_GENERATOR: Boolean or import string, default is False.
        3. OAUTH2_TOKEN_EXPIRES_IN: Dict or import string, default is None.

        By default, it will not generate ``refresh_token``, which can be turn on by
        configure ``OAUTH2_REFRESH_TOKEN_GENERATOR``.

        Here are some examples of the token generator::

            OAUTH2_ACCESS_TOKEN_GENERATOR = "your_project.generators.gen_token"

            # and in module `your_project.generators`, you can define:


            def gen_token(client, grant_type, user, scope):
                # generate token according to these parameters
                token = create_random_token()
                return f"{client.id}-{user.id}-{token}"

        Here is an example of ``OAUTH2_TOKEN_EXPIRES_IN``::

            OAUTH2_TOKEN_EXPIRES_IN = {
                "authorization_code": 864000,
                "urn:ietf:params:oauth:grant-type:jwt-bearer": 3600,
            }
        """
        conf = config.get("OAUTH2_ACCESS_TOKEN_GENERATOR", True)
        access_token_generator = create_token_generator(conf, 42)

        conf = config.get("OAUTH2_REFRESH_TOKEN_GENERATOR", False)
        refresh_token_generator = create_token_generator(conf, 48)

        expires_conf = config.get("OAUTH2_TOKEN_EXPIRES_IN")
        expires_generator = create_token_expires_in_generator(expires_conf)
        return BearerTokenGenerator(
            access_token_generator, refresh_token_generator, expires_generator
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
