import inspect
import json
from contextvars import ContextVar

from fastapi import Request
from fastapi import Response

from authlib.integrations.base_client import InvalidTokenError
from authlib.integrations.fastapi_oauth2.errors import raise_http_exception
from authlib.integrations.fastapi_oauth2.requests import FastApiJsonRequest
from authlib.integrations.fastapi_oauth2.signals import token_authenticated
from authlib.oauth2 import OAuth2Error
from authlib.oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6750 import InsufficientScopeError

_current_request = ContextVar("authlib_server_oauth2_request", default=None)


class OAuth2Dependency:
    """FastAPI dependency that validates the OAuth2 access token."""

    def __init__(self, protector, scopes, optional, kwargs):
        self.protector = protector
        self.scopes = scopes
        self.optional = optional
        self.kwargs = kwargs

    async def __call__(self, request: Request):
        oauth2_request = FastApiJsonRequest(request)
        current_scopes = self.scopes(request) if callable(self.scopes) else self.scopes

        claims = dict(self.kwargs)
        claims["scopes"] = current_scopes

        try:
            token = self.protector.validate_request(request=oauth2_request, **claims)
            token_authenticated.send(self.protector, token=token)
            request.state.oauth2_token = token
            return token
        except MissingAuthorizationError as error:
            if self.optional:
                return None
            self.protector.raise_error_response(error)
        except OAuth2Error as error:
            self.protector.raise_error_response(error)


class ResourceProtector(_ResourceProtector):
    def raise_error_response(self, error):
        status = error.status_code
        body = json.dumps(dict(error.get_body()))
        headers = dict(error.get_headers())
        raise_http_exception(status, body, headers)

    def handle_error_response(self, error):
        status = error.status_code
        body = json.dumps(dict(error.get_body()))
        headers = dict(error.get_headers())
        return Response(
            body, status_code=status, headers=headers, media_type="application/json"
        )

    def __call__(self, scopes=None, optional=False, **kwargs):
        """Return a dependency instance for use with FastAPI's Depends."""
        return OAuth2Dependency(self, scopes, optional, kwargs)

    def validate_token(self, token, scopes, request):
        print("SCOPES:", scopes)
        print("TOKEN SCOPES:", token.scopes if token else None)

        if token is None or token.is_revoked():
            raise InvalidTokenError()

        if not set(scopes).issubset(set(token.scopes)):
            raise InsufficientScopeError()


async def _call_endpoint(f, *args, **kwargs):
    result = f(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


class _CurrentTokenProxy:
    """Proxy that resolves the current request's OAuth2 token."""

    def _token(self):
        request = _current_request.get()

        if request is None:
            raise RuntimeError("No request found in the current context.")

        token = getattr(request.state, "oauth2_token", None)

        if token is None:
            raise RuntimeError(
                "No OAuth2 token found in the current context. Make sure "
                "the endpoint is protected with ``require_oauth``."
            )

        return token

    def __getattr__(self, name):
        return getattr(self._token(), name)

    def __repr__(self):
        return repr(self._token())


current_token = _CurrentTokenProxy()
