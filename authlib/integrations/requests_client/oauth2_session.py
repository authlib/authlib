from requests import Response
from requests import Session
from requests.auth import AuthBase

from authlib.oauth2.client import OAuth2Client
from .utils import update_session_configure
from ..base_client import InvalidTokenError
from ..base_client import MissingTokenError
from ..base_client import OAuthError
from ...oauth2 import TokenAuth
from ...oauth2.auth import AuthProtocol

__all__ = ["OAuth2Session", "OAuth2Auth"]


class OAuth2TokenAuth(TokenAuth):

    def ensure_active_token(self):
        if self.client and not self.client.ensure_active_token(self.token):
            raise InvalidTokenError()

    def prepare(self, method, uri, headers, body):
        self.ensure_active_token()
        return super().prepare(method, uri, headers, body)


class OAuth2Auth(AuthBase):
    """Sign requests for OAuth 2.0"""

    def __init__(self, auth: AuthProtocol):
        self.auth = auth

    def __call__(self, request):
        request.url, request.headers, request.body = self.auth.prepare(
            request.method, request.url, request.headers, request.body
        )
        request.register_hook("response", self.retry_if_necessary)
        return request

    def retry_if_necessary(self, response: Response, **kwargs):
        if not self.auth.should_retry(response):
            return response

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response.content()
        response.close()
        new_request = response.request.copy()

        new_request.url, new_request.headers, new_request.body = self.auth.prepare_retry(
            new_request.method, new_request.url, new_request.headers, new_request.body
        )
        new_response = response.connection.send(new_request, **kwargs)
        new_response.history.append(response)
        new_response.request = new_request
        return new_response


class OAuth2Session(OAuth2Client, Session):
    """Construct a new OAuth 2 client requests session.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param authorization_endpoint: URL of the authorization server's
        authorization endpoint.
    :param token_endpoint: URL of the authorization server's token endpoint.
    :param token_endpoint_auth_method: client authentication method for
        token endpoint.
    :param revocation_endpoint: URL of the authorization server's OAuth 2.0
        revocation endpoint.
    :param revocation_endpoint_auth_method: client authentication method for
        revocation endpoint.
    :param scope: Scope that you needed to access user resources.
    :param state: Shared secret to prevent CSRF attack.
    :param redirect_uri: Redirect URI you registered as callback.
    :param token: A dict of token attributes such as ``access_token``,
        ``token_type`` and ``expires_at``.
    :param token_placement: The place to put token in HTTP request. Available
        values: "header", "body", "uri".
    :param update_token: A function for you to update token. It accept a
        :class:`OAuth2Token` as parameter.
    :param leeway: Time window in seconds before the actual expiration of the
        authentication token, that the token is considered expired and will
        be refreshed.
    :param default_timeout: If settled, every requests will have a default timeout.
    """

    auth_class = OAuth2Auth
    token_auth_class = OAuth2TokenAuth
    oauth_error_class = OAuthError
    SESSION_REQUEST_PARAMS = (
        "allow_redirects",
        "timeout",
        "cookies",
        "files",
        "proxies",
        "hooks",
        "stream",
        "verify",
        "cert",
        "json",
    )

    def __init__(
        self,
        client_id=None,
        client_secret=None,
        token_endpoint_auth_method=None,
        revocation_endpoint_auth_method=None,
        scope=None,
        state=None,
        redirect_uri=None,
        token=None,
        token_placement="header",
        update_token=None,
        leeway=60,
        default_timeout=None,
        **kwargs,
    ):
        Session.__init__(self)
        self.default_timeout = default_timeout
        update_session_configure(self, kwargs)

        OAuth2Client.__init__(
            self,
            session=self,
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            token=token,
            token_placement=token_placement,
            update_token=update_token,
            leeway=leeway,
            **kwargs,
        )

    def fetch_access_token(self, url=None, **kwargs):
        """Alias for fetch_token."""
        return self.fetch_token(url, **kwargs)

    def request(self, method, url, withhold_token=False, auth=None, **kwargs):
        """Send request with auto refresh token feature (if available)."""
        if self.default_timeout:
            kwargs.setdefault("timeout", self.default_timeout)
        if not withhold_token and auth is None:
            if not self.token:
                raise MissingTokenError()
            if not self.ensure_active_token(self.token):
                raise InvalidTokenError()
            auth = self.protected_auth
        return super().request(method, url, auth=auth, **kwargs)
