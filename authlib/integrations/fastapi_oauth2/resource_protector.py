import functools
import inspect
import json
from contextlib import contextmanager
from contextvars import ContextVar

from fastapi.responses import Response

from authlib.oauth2 import OAuth2Error
from authlib.oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError

from .errors import raise_http_exception
from .requests import FastApiJsonRequest
from .signals import token_authenticated

_current_token = ContextVar("authlib_server_oauth2_token", default=None)


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Creating a ``require_oauth``
    decorator easily with ResourceProtector::

        from authlib.integrations.flask_oauth2.fastapi_oauth2 import ResourceProtector

        require_oauth = ResourceProtector()

        # add bearer token validator
        from authlib.oauth2.rfc6750 import BearerTokenValidator
        from project.models import Token


        class MyBearerTokenValidator(BearerTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()


        require_oauth.register_token_validator(MyBearerTokenValidator())

        # protect resource with require_oauth


        @app.get("/user")
        @require_oauth(["profile"])
        async def user_profile(request: Request):
            user = User.get(current_token.user_id)
            return user.to_dict()

    The protected endpoint must declare a ``request: Request`` parameter, so
    that the decorator can validate the current request.
    """

    def raise_error_response(self, error):
        status = error.status_code
        body = json.dumps(dict(error.get_body()))
        headers = dict(error.get_headers())  # Convert list of tuples to dict
        raise_http_exception(status, body, headers)

    def handle_error_response(self, error):
        status = error.status_code
        body = json.dumps(dict(error.get_body()))
        headers = dict(error.get_headers())  # Convert list of tuples to dict
        return Response(
            body, status_code=status, headers=headers, media_type="application/json"
        )

    def acquire_token(self, request=None, scopes=None, **kwargs):
        if request is None:
            raise RuntimeError(
                "acquire_token() requires the FastAPI/Starlette request, since "
                "FastAPI has no global request proxy. Protected endpoints must "
                "declare a 'request: Request' parameter."
            )
        oauth2_request = FastApiJsonRequest(request)
        # backward compatibility
        kwargs["scopes"] = scopes
        for claim in kwargs:
            if isinstance(kwargs[claim], str):
                kwargs[claim] = [kwargs[claim]]
        token = self.validate_request(request=oauth2_request, **kwargs)
        token_authenticated.send(self, token=token)
        _current_token.set(token)
        return token

    @contextmanager
    def acquire(self, request=None, scopes=None):
        try:
            yield self.acquire_token(request, scopes)
        except OAuth2Error as error:
            self.raise_error_response(error)

    def __call__(self, *args, **kwargs):
        if len(args) == 1 and callable(args[0]) and not kwargs:
            return self.decorator()(args[0])

        return self.decorator(*args, **kwargs)

    def decorator(self, scopes=None, optional=False, **kwargs):
        claims = dict(kwargs)

        def inner(f):
            @functools.wraps(f)
            async def decorated(*args, **kwargs):
                request = kwargs.get("request")

                # Calculate dynamic scopes for each request.
                current_scopes = scopes(request) if callable(scopes) else scopes

                current_claims = dict(claims)
                current_claims["scopes"] = current_scopes

                try:
                    self.acquire_token(request, **current_claims)
                except MissingAuthorizationError as error:
                    if optional:
                        return await _call_endpoint(f, *args, **kwargs)
                    return self.handle_error_response(error)
                except OAuth2Error as error:
                    return self.handle_error_response(error)

                return await _call_endpoint(f, *args, **kwargs)

            return decorated

        return inner


async def _call_endpoint(f, *args, **kwargs):
    result = f(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


class _CurrentTokenProxy:
    """Proxy object that resolves to the token of the current request."""

    def _token(self):
        token = _current_token.get()
        if token is None:
            raise RuntimeError(
                "No OAuth2 token found in the current context. Make sure the "
                "endpoint is protected with ``require_oauth``."
            )
        return token

    def __getattr__(self, name):
        return getattr(self._token(), name)

    def __repr__(self):
        return repr(self._token())


current_token = _CurrentTokenProxy()
