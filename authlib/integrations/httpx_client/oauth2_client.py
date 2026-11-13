# ruff: noqa: I001
# The import order below is intentional: httpx compatibility must be loaded
# before anyio so import errors refer to httpx.
import time
from collections.abc import Generator
from contextlib import asynccontextmanager

from ._compat import httpx2
from anyio import Lock  # Import after httpx so import errors refer to httpx
from anyio import sleep

from authlib.common.encoding import to_unicode
from authlib.common.errors import AuthlibBaseError
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.auth import TokenAuth
from authlib.oauth2.client import DEFAULT_HEADERS
from authlib.oauth2.client import OAuth2Client as _OAuth2Client
from authlib.oauth2.client import _form_data
from authlib.oauth2.client import _load_token_response
from authlib.oauth2.rfc8628 import DEVICE_CODE_GRANT_TYPE
from authlib.oauth2.rfc8628 import prepare_device_authorization_request
from authlib.oauth2.rfc8628.errors import AuthorizationPendingError
from authlib.oauth2.rfc8628.errors import SlowDownError

from ..base_client import InvalidTokenError
from ..base_client import MissingTokenError
from ..base_client import OAuthError
from ..base_client import UnsupportedTokenTypeError
from .utils import HTTPX_CLIENT_KWARGS
from .utils import build_request

USE_CLIENT_DEFAULT = httpx2.USE_CLIENT_DEFAULT
Auth = httpx2.Auth
Request = httpx2.Request
Response = httpx2.Response

__all__ = [
    "OAuth2Auth",
    "OAuth2ClientAuth",
    "AsyncOAuth2Client",
    "OAuth2Client",
]


class OAuth2Auth(Auth, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""

    requires_request_body = True

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        try:
            url, headers, body = self.prepare(
                str(request.url), request.headers, request.content
            )
            headers["Content-Length"] = str(len(body))
            yield build_request(
                url=url, headers=headers, body=body, initial_request=request
            )
        except KeyError as error:
            description = f"Unsupported token_type: {str(error)}"
            raise UnsupportedTokenTypeError(description=description) from error


class OAuth2ClientAuth(Auth, ClientAuth):
    requires_request_body = True

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        url, headers, body = self.prepare(
            request.method, str(request.url), request.headers, request.content
        )
        headers["Content-Length"] = str(len(body))
        yield build_request(
            url=url, headers=headers, body=body, initial_request=request
        )


class AsyncOAuth2Client(_OAuth2Client, httpx2.AsyncClient):
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth
    oauth_error_class = OAuthError

    def __init__(
        self,
        client_id=None,
        client_secret=None,
        token_endpoint_auth_method=None,
        revocation_endpoint_auth_method=None,
        scope=None,
        redirect_uri=None,
        token=None,
        token_placement="header",
        update_token=None,
        leeway=60,
        **kwargs,
    ):
        # extract httpx2.Client kwargs
        client_kwargs = self._extract_session_request_params(kwargs)
        super(_OAuth2Client, self).__init__(**client_kwargs)

        # We use a Lock to synchronize coroutines to prevent
        # multiple concurrent attempts to refresh the same token
        self._token_refresh_lock = Lock()

        _OAuth2Client.__init__(
            self,
            session=None,
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope,
            redirect_uri=redirect_uri,
            token=token,
            token_placement=token_placement,
            update_token=update_token,
            leeway=leeway,
            **kwargs,
        )

    async def _ensure_initial_token(self):
        """Fetch a missing client-credentials token, once per client."""
        if self.token:
            return
        token_endpoint = self.metadata.get("token_endpoint")
        if (
            self.metadata.get("grant_type") != "client_credentials"
            or not token_endpoint
        ):
            raise MissingTokenError()
        async with self._token_refresh_lock:
            if not self.token:
                await self.fetch_token(token_endpoint, grant_type="client_credentials")

    async def request(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            await self._ensure_initial_token()
            await self.ensure_active_token(self.token)
            auth = self.token_auth

        return await super().request(method, url, auth=auth, **kwargs)

    @asynccontextmanager
    async def stream(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            await self._ensure_initial_token()
            await self.ensure_active_token(self.token)
            auth = self.token_auth

        async with super().stream(method, url, auth=auth, **kwargs) as resp:
            yield resp

    async def ensure_active_token(self, token=None):
        async with self._token_refresh_lock:
            token = self.token or token
            if not token.is_expired(leeway=self.leeway):
                return True

            refresh_token = token.get("refresh_token")
            url = self.metadata.get("token_endpoint")
            if refresh_token and url:
                await self.refresh_token(url, refresh_token=refresh_token)
                return True

            if self.metadata.get("grant_type") != "client_credentials":
                raise InvalidTokenError()

            access_token = token["access_token"]
            new_token = await self.fetch_token(url, grant_type="client_credentials")
            if self.update_token:
                await self.update_token(new_token, access_token=access_token)

            return True

    async def _fetch_token(
        self,
        url,
        body="",
        headers=None,
        auth=USE_CLIENT_DEFAULT,
        method="POST",
        **kwargs,
    ):
        if method.upper() == "POST":
            resp = await self.post(
                url, data=_form_data(body), headers=headers, auth=auth, **kwargs
            )
        else:
            if "?" in url:
                url = "&".join([url, body])
            else:
                url = "?".join([url, body])
            resp = await self.get(url, headers=headers, auth=auth, **kwargs)

        for hook in self.compliance_hook["access_token_response"]:
            resp = hook(resp)

        return self.parse_response_token(resp)

    async def _refresh_token(
        self,
        url,
        refresh_token=None,
        body="",
        headers=None,
        auth=USE_CLIENT_DEFAULT,
        **kwargs,
    ):
        resp = await self.post(
            url, data=_form_data(body), headers=headers, auth=auth, **kwargs
        )

        for hook in self.compliance_hook["refresh_token_response"]:
            resp = hook(resp)

        token = self.parse_response_token(resp)
        if "refresh_token" not in token:
            self.token["refresh_token"] = refresh_token

        if self.update_token:
            await self.update_token(self.token, refresh_token=refresh_token)

        return self.token

    def _http_post(
        self, url, body=None, auth=USE_CLIENT_DEFAULT, headers=None, **kwargs
    ):
        return self.post(
            url, data=_form_data(body), headers=headers, auth=auth, **kwargs
        )

    async def fetch_device_authorization(
        self,
        url=None,
        scope=None,
        body="",
        auth=None,
        headers=None,
        **kwargs,
    ):
        """Send a device authorization request, per :rfc:`8628#section-3.1`.

        :param url: Device authorization endpoint URL. If omitted, the
                    ``device_authorization_endpoint`` value from the client
                    metadata is used.
        :param scope: The scope of the access request, as a string or a list.
                      Defaults to the scope of the client.
        :param body: Optional application/x-www-form-urlencoded body to extend.
        :param auth: An auth tuple or method as accepted by the session.
        :param headers: Dict of default request headers.
        :param kwargs: Extra parameters for the device authorization request.
        :return: The device authorization response as a dict, containing
                 ``device_code``, ``user_code``, ``verification_uri`` and
                 optionally ``verification_uri_complete``, ``expires_in``
                 and ``interval``.
        """
        if url is None:
            url = self.metadata.get("device_authorization_endpoint")
        if not url:
            raise ValueError("Missing device authorization endpoint URL.")

        session_kwargs = self._extract_session_request_params(kwargs)
        if scope is None:
            scope = self.scope
        body = prepare_device_authorization_request(scope=scope, body=body, **kwargs)

        if auth is None:
            auth = self.client_auth(self.token_endpoint_auth_method)
        if headers is None:
            headers = DEFAULT_HEADERS

        resp = await self.post(
            to_unicode(url),
            data=_form_data(body),
            headers=headers,
            auth=auth,
            **session_kwargs,
        )
        data = _load_token_response(resp)
        if "error" in data:
            raise self.oauth_error_class(
                error=data["error"], description=data.get("error_description")
            )
        return data

    async def poll_device_token(
        self, device_code, url=None, interval=5, timeout=None, **kwargs
    ):
        """Poll the token endpoint until the user completes or declines the
        device authorization, per :rfc:`8628#section-3.5`.

        The ``authorization_pending`` error is answered with another poll
        after ``interval`` seconds; on ``slow_down`` the interval is
        increased by 5 seconds, as the specification requires. The
        ``expired_token`` and ``access_denied`` errors, and any other
        error, are raised to the caller.

        :param device_code: The device verification code returned by
                            :meth:`fetch_device_authorization`.
        :param url: Token endpoint URL. If omitted, the ``token_endpoint``
                    value from the client metadata is used.
        :param interval: Seconds to wait between polls; use the ``interval``
                         value from the device authorization response.
                         Defaults to 5.
        :param timeout: Maximum seconds to poll before raising
                        ``TimeoutError``. Unlimited by default: the server
                        ends the session with an ``expired_token`` error
                        once the device code expires.
        :param kwargs: Extra parameters for the token request.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        if url is None:
            url = self.metadata.get("token_endpoint")
        if not url:
            raise ValueError("Missing token endpoint URL.")

        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                return await self.fetch_token(
                    url,
                    grant_type=DEVICE_CODE_GRANT_TYPE,
                    device_code=device_code,
                    **kwargs,
                )
            except AuthlibBaseError as error:
                if error.error == SlowDownError.error:
                    interval += 5
                elif error.error != AuthorizationPendingError.error:
                    raise
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("Device authorization timed out.")
            await sleep(interval)


class OAuth2Client(_OAuth2Client, httpx2.Client):
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth
    oauth_error_class = OAuthError

    def __init__(
        self,
        client_id=None,
        client_secret=None,
        token_endpoint_auth_method=None,
        revocation_endpoint_auth_method=None,
        scope=None,
        redirect_uri=None,
        token=None,
        token_placement="header",
        update_token=None,
        **kwargs,
    ):
        # extract httpx2.Client kwargs
        client_kwargs = self._extract_session_request_params(kwargs)
        super(_OAuth2Client, self).__init__(**client_kwargs)

        _OAuth2Client.__init__(
            self,
            session=self,
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope,
            redirect_uri=redirect_uri,
            token=token,
            token_placement=token_placement,
            update_token=update_token,
            **kwargs,
        )

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)

    def _ensure_initial_token(self):
        """Fetch a missing token for a configured client-credentials grant."""
        if self.token:
            return
        token_endpoint = self.metadata.get("token_endpoint")
        if (
            self.metadata.get("grant_type") != "client_credentials"
            or not token_endpoint
        ):
            raise MissingTokenError()
        self.fetch_token(token_endpoint, grant_type="client_credentials")

    def request(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            self._ensure_initial_token()
            if not self.ensure_active_token(self.token):
                raise InvalidTokenError()
            auth = self.token_auth

        return super().request(method, url, auth=auth, **kwargs)

    def stream(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            self._ensure_initial_token()
            if not self.ensure_active_token(self.token):
                raise InvalidTokenError()
            auth = self.token_auth

        return super().stream(method, url, auth=auth, **kwargs)
