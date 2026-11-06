from authlib.common.urls import add_params_to_uri
from authlib.consts import default_json_headers
from authlib.deprecate import deprecate


class OAuth2Response:
    """A response of the authorization server, before it is sent.

    Grants and endpoints return it. The authorization server turns it into a
    framework response with
    :meth:`~authlib.oauth2.rfc6749.AuthorizationServer.encode_response`.

    :param status_code: the HTTP status code
    :param body: the response body. A ``dict`` is sent as JSON.
    :param headers: a list of ``(name, value)`` pairs
    """

    def __init__(self, status_code, body="", headers=None):
        self.status_code = status_code
        self.body = body
        self.headers = list(headers or [])
        self._tuple_deprecated = False

    def __iter__(self):
        return iter(self._as_tuple())

    def __getitem__(self, index):
        return self._as_tuple()[index]

    def _as_tuple(self):
        if not self._tuple_deprecated:
            self._tuple_deprecated = True
            _deprecate_tuple()

        return self._legacy_tuple()

    def _legacy_tuple(self):
        return self.status_code, self.body, self.headers


class JsonResponse(OAuth2Response):
    """A JSON response. By default, clients and proxies must not cache it.

    :param data: a ``dict`` sent as JSON
    :param status_code: the HTTP status code
    :param headers: a list of ``(name, value)`` pairs
    """

    def __init__(self, data, status_code=200, headers=None):
        if headers is None:
            headers = default_json_headers
        super().__init__(status_code, data, headers)


class RedirectResponse(OAuth2Response):
    """A redirection to another URI, with the 303 status code.

    Per :rfc:`9700#section-4.12`, the browser then uses GET, even after a POST.

    :param location: the URI to redirect to
    """

    def __init__(self, location):
        super().__init__(303, "", [("Location", location)])


class AuthorizationResponse(OAuth2Response):
    """The parameters that the authorization endpoint sends to the client.

    The authorization server encodes them according to the response mode,
    with :meth:`~authlib.oauth2.rfc6749.AuthorizationServer.encode_authorization_response`.
    The encoding sets the body, and the status code if it is not set.

    :param redirect_uri: the redirect URI of the client
    :param params: a list of ``(name, value)`` pairs
    :param response_mode: ``query`` or ``fragment``
    """

    def __init__(self, redirect_uri, params, response_mode="query"):
        super().__init__(None, None)
        self.redirect_uri = redirect_uri
        self.params = params
        self.response_mode = response_mode

    def _legacy_tuple(self):
        return _encode_redirect(self)._legacy_tuple()


def _encode_redirect(response):
    """Encode an authorization response as a redirection to the client."""
    if response.response_mode not in ("query", "fragment"):
        raise ValueError(f"Unsupported response mode: {response.response_mode!r}")

    fragment = response.response_mode == "fragment"
    uri = add_params_to_uri(response.redirect_uri, response.params, fragment=fragment)
    redirect = RedirectResponse(uri)
    if response.status_code is not None:
        redirect.status_code = response.status_code

    redirect.headers.extend(response.headers)
    return redirect


def _deprecate_tuple():
    deprecate(
        "Grants and endpoints return an 'OAuth2Response'. "
        "Using it as a '(status_code, body, headers)' tuple is deprecated. "
        "Use its 'status_code', 'body' and 'headers' attributes instead.",
        version="1.11",
        stacklevel=5,
    )
