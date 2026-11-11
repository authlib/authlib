from authlib.deprecate import accepts_argument
from authlib.deprecate import deprecate

from ..rfc6749.errors import InvalidScopeError


class BearerTokenGenerator:
    """Bearer token generator which can create the payload for token response
    by OAuth 2 server. A typical token response would be:

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store
        Pragma: no-cache

        {
            "access_token":"mF_9.B5f-4.1JqM",
            "token_type":"Bearer",
            "expires_in":3600,
            "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
        }

    :param access_token_generator: a function that returns the access token.
        It receives ``client``, ``grant_type``, ``user``, ``scope`` and
        ``expires_in``, the lifetime of the token in seconds.
    :param refresh_token_generator: a function that returns the refresh token.
        It receives ``client``, ``grant_type``, ``user`` and ``scope``.
    :param expires_generator: the lifetime of the access tokens, as a number of
        seconds or a function that receives ``client`` and ``grant_type``.
    """

    #: default expires_in value
    DEFAULT_EXPIRES_IN = 3600
    #: default expires_in value differentiate by grant_type
    GRANT_TYPES_EXPIRES_IN = {
        "authorization_code": 864000,
        "implicit": 3600,
        "password": 864000,
        "client_credentials": 864000,
    }

    def __init__(
        self,
        access_token_generator,
        refresh_token_generator=None,
        expires_generator=None,
    ):
        self.access_token_generator = access_token_generator
        self.refresh_token_generator = refresh_token_generator
        self.expires_generator = expires_generator
        if access_token_generator is not None and not accepts_argument(
            access_token_generator, "expires_in"
        ):
            name = getattr(access_token_generator, "__qualname__", None)
            deprecate(
                f"The access token generator {name or access_token_generator!r} "
                "does not accept an 'expires_in' argument. "
                "In 1.11, it will always receive it.",
            )

    def _get_expires_in(self, client, grant_type):
        if self.expires_generator is None:
            expires_in = self.GRANT_TYPES_EXPIRES_IN.get(
                grant_type, self.DEFAULT_EXPIRES_IN
            )
        elif callable(self.expires_generator):
            expires_in = self.expires_generator(client, grant_type)
        elif isinstance(self.expires_generator, int):
            expires_in = self.expires_generator
        else:
            expires_in = self.DEFAULT_EXPIRES_IN
        return expires_in

    @staticmethod
    def get_allowed_scope(client, scope):
        """Get the allowed scope for token generation.

        Per RFC 6749 Section 3.3, if the client omits the scope parameter,
        the authorization server MUST either process the request using a
        pre-defined default value or fail the request indicating an invalid scope.

        :param client: the client making the request
        :param scope: the requested scope (may be None if omitted)
        :return: the allowed scope string
        :raises InvalidScopeError: if client.get_allowed_scope returns None
        """
        scope = client.get_allowed_scope(scope)
        if scope is None:
            raise InvalidScopeError()
        return scope

    def generate(
        self,
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        """Generate a bearer token for OAuth 2.0 authorization token endpoint.

        :param client: the client that making the request.
        :param grant_type: current requested grant_type.
        :param user: current authorized user.
        :param expires_in: if provided, use this value as expires_in.
        :param scope: current requested scope.
        :param include_refresh_token: should refresh_token be included.
        :return: Token dict
        """
        scope = self.get_allowed_scope(client, scope)
        if expires_in is None:
            expires_in = self._get_expires_in(client, grant_type)

        kwargs = {
            "client": client,
            "grant_type": grant_type,
            "user": user,
            "scope": scope,
        }
        if accepts_argument(self.access_token_generator, "expires_in"):
            kwargs["expires_in"] = expires_in

        access_token = self.access_token_generator(**kwargs)
        token = {
            "token_type": "Bearer",
            "access_token": access_token,
        }
        if expires_in:
            token["expires_in"] = expires_in
        if include_refresh_token and self.refresh_token_generator:
            token["refresh_token"] = self.refresh_token_generator(
                client=client, grant_type=grant_type, user=user, scope=scope
            )
        if scope:
            token["scope"] = scope
        return token

    def __call__(
        self,
        grant_type,
        client,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
    ):
        return self.generate(
            grant_type, client, user, scope, expires_in, include_refresh_token
        )
