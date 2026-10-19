import typing

from authlib.common.encoding import to_unicode
from authlib.oauth1 import SIGNATURE_HMAC_SHA1
from authlib.oauth1 import SIGNATURE_TYPE_HEADER
from authlib.oauth1 import ClientAuth
from authlib.oauth1.client import OAuth1Client as _OAuth1Client

from ..base_client import OAuthError
from ._compat import httpx2
from .utils import build_request
from .utils import extract_client_kwargs

Auth = httpx2.Auth
Request = httpx2.Request
Response = httpx2.Response


class OAuth1Auth(Auth, ClientAuth):
    """Signs the httpx2 request using OAuth 1 (RFC5849)."""

    requires_request_body = True

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        url, headers, body = self.prepare(
            request.method, str(request.url), request.headers, request.content
        )
        headers["Content-Length"] = str(len(body))
        yield build_request(
            url=url, headers=headers, body=body, initial_request=request
        )


class AsyncOAuth1Client(_OAuth1Client, httpx2.AsyncClient):
    auth_class = OAuth1Auth

    def __init__(
        self,
        client_id,
        client_secret=None,
        token=None,
        token_secret=None,
        redirect_uri=None,
        rsa_key=None,
        verifier=None,
        signature_method=SIGNATURE_HMAC_SHA1,
        signature_type=SIGNATURE_TYPE_HEADER,
        force_include_body=False,
        **kwargs,
    ):
        _client_kwargs = extract_client_kwargs(kwargs)
        httpx2.AsyncClient.__init__(self, **_client_kwargs)

        _OAuth1Client.__init__(
            self,
            None,
            client_id=client_id,
            client_secret=client_secret,
            token=token,
            token_secret=token_secret,
            redirect_uri=redirect_uri,
            rsa_key=rsa_key,
            verifier=verifier,
            signature_method=signature_method,
            signature_type=signature_type,
            force_include_body=force_include_body,
            **kwargs,
        )

    async def fetch_access_token(self, url, verifier=None, **kwargs):
        """Method for fetching an access token from the token endpoint.

        This is the final step in the OAuth 1 workflow. An access token is
        obtained using all previously obtained credentials, including the
        verifier from the authorization step.

        :param url: Access Token endpoint.
        :param verifier: A verifier string to prove authorization was granted.
        :param kwargs: Extra parameters to include for fetching access token.
        :return: A token dict.
        """
        if verifier:
            self.auth.verifier = verifier
        if not self.auth.verifier:
            self.handle_error("missing_verifier", 'Missing "verifier" value')
        token = await self._fetch_token(url, **kwargs)
        self.auth.verifier = None
        return token

    async def _fetch_token(self, url, **kwargs):
        resp = await self.post(url, **kwargs)
        text = await resp.aread()
        token = self.parse_response_token(resp.status_code, to_unicode(text))
        self.token = token
        return token

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)


class OAuth1Client(_OAuth1Client, httpx2.Client):
    auth_class = OAuth1Auth

    def __init__(
        self,
        client_id,
        client_secret=None,
        token=None,
        token_secret=None,
        redirect_uri=None,
        rsa_key=None,
        verifier=None,
        signature_method=SIGNATURE_HMAC_SHA1,
        signature_type=SIGNATURE_TYPE_HEADER,
        force_include_body=False,
        **kwargs,
    ):
        _client_kwargs = extract_client_kwargs(kwargs)
        httpx2.Client.__init__(self, **_client_kwargs)

        _OAuth1Client.__init__(
            self,
            self,
            client_id=client_id,
            client_secret=client_secret,
            token=token,
            token_secret=token_secret,
            redirect_uri=redirect_uri,
            rsa_key=rsa_key,
            verifier=verifier,
            signature_method=signature_method,
            signature_type=signature_type,
            force_include_body=force_include_body,
            **kwargs,
        )

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)
