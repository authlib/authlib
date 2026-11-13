import inspect
import time

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token
from authlib.deprecate import accepts_argument
from authlib.deprecate import deprecate
from authlib.oauth2.rfc6750.token import BearerTokenGenerator


class JWTBearerTokenGenerator(BearerTokenGenerator):
    r"""A JWT formatted access token generator.

    :param issuer: The issuer identifier. Will appear in the JWT ``iss`` claim.

    :param \\*\\*kwargs: Other parameters are inherited from
        :class:`~authlib.oauth2.rfc6750.token.BearerTokenGenerator`.

    This token generator can be registered into the authorization server::

        class MyJWTBearerTokenGenerator(JWTBearerTokenGenerator):
            def get_jwks(self): ...

            def get_extra_claims(self, client, grant_type, user, scope, request): ...

            def get_audiences(self, client, user, scope, request):
                return "https://resource-server.example.org"


        authorization_server.register_token_generator(
            "default",
            MyJWTBearerTokenGenerator(
                issuer="https://authorization-server.example.org"
            ),
        )
    """

    def __init__(
        self,
        issuer,
        alg="RS256",
        refresh_token_generator=None,
        expires_generator=None,
    ):
        super().__init__(
            self.access_token_generator, refresh_token_generator, expires_generator
        )
        self.issuer = issuer
        self.alg = alg
        self._client_id_audience_warned = False
        self._hooks_warned = set()

    def get_jwks(self):
        """Return the JWKs that will be used to sign the JWT access token.
        Developers MUST re-implement this method::

            def get_jwks(self):
                return load_jwks("jwks.json")
        """
        raise NotImplementedError()

    def get_extra_claims(self, client, grant_type, user, scope, request=None):
        """Return extra claims to add in the JWT access token. Developers MAY
        re-implement this method to add identity claims like the ones in
        :ref:`specs/oidc` ID Token, or any other arbitrary claims::

            def get_extra_claims(self, client, grant_type, user, scope, request):
                return generate_user_info(user, scope)

        :param client: the client that makes the request.
        :param grant_type: the requested grant type.
        :param user: the authorized user.
        :param scope: the granted scope.
        :param request: the current request, or ``None``.
        """
        return {}

    def get_audiences(self, client, user, scope, request=None) -> str | list[str]:
        """Return the identifier of the resource, or the list of identifiers,
        that receives the token. Developers MUST re-implement this method. The
        result can depend on the client, the user, the scope or the request::

            def get_audiences(self, client, user, scope, request):
                if "admin" in scope_to_list(scope):
                    return [API_URL, ADMIN_API_URL]
                return API_URL

        The default implementation returns the client ID. It is deprecated, and
        will raise :class:`NotImplementedError` in 1.11, like :meth:`get_jwks`.

        :param client: the client that makes the request.
        :param user: the authorized user.
        :param scope: the granted scope.
        :param request: the current request, or ``None``.
        """
        if not self._client_id_audience_warned:
            self._client_id_audience_warned = True
            deprecate(
                f"'{type(self).__name__}' puts the client ID in the 'aud' claim. "
                "Override 'get_audiences' to return the resource identifiers. "
                "In 1.11, the default 'get_audiences' will raise "
                "'NotImplementedError'.",
            )

        return client.get_client_id()

    def get_acr(self, request) -> str | None:
        """Authentication Context Class Reference.
        Return a case sensitive string that tells the class of authentication
        that the user performed. The token audience may refuse some resources
        if some ACR criteria are not met. :ref:`specs/oidc` defines one special
        value: ``0`` means that the user authentication did not respect
        `ISO29115`_ level 1, and will be refused monetary operations. See
        :meth:`get_auth_time` to find the authentication of the token.
        Developers MAY re-implement this method::

            def get_acr(self, request):
                if request and request.authorization_code:
                    return request.authorization_code.get_acr()
                return None

        :param request: the current request, or ``None``.

        .. _ISO29115: https://www.iso.org/standard/45138.html
        """
        return None

    def get_auth_time(self, request) -> int | None:
        """User authentication time.
        Return the time when the user authenticated, as a number of seconds
        since 1970-01-01T00:00:00Z UTC. Developers MAY re-implement this method.

        The value belongs to the authentication that the token comes from, not
        to the user. The request gives access to it:

        - at the token endpoint, ``request.authorization_code``,
          ``request.refresh_token`` or ``request.credential`` hold the grant;
        - at the authorization endpoint, the OpenID Connect implicit and hybrid
          grants set ``request.auth_time``, ``request.acr`` and ``request.amr``.
          Other grants do not set these attributes.

        ``request.refresh_token`` is the token object that
        ``authenticate_refresh_token`` returns. Store the authentication values
        on it to keep them in refreshed access tokens::

            def get_auth_time(self, request):
                if request is None:
                    return None
                if request.authorization_code:
                    return request.authorization_code.get_auth_time()
                if request.refresh_token:
                    return request.refresh_token.get_auth_time()
                return None

        :param request: the current request, or ``None``.
        """
        return None

    def get_amr(self, request) -> list[str] | None:
        """Authentication Methods References.
        Return the list of case sensitive strings that tell which
        authentication methods the user used, as defined by :ref:`specs/oidc`.
        See :meth:`get_auth_time` to find the authentication of the token.
        Developers MAY re-implement this method::

            def get_amr(self, request):
                if request and request.authorization_code:
                    return request.authorization_code.get_amr()
                return None

        :param request: the current request, or ``None``.
        """
        return None

    def get_jti(self, client, grant_type, user, scope, request=None) -> str:
        """JWT ID.
        Create an unique identifier for the token. Developers MAY re-implement
        this method::

            def get_jti(self, client, grant_type, user, scope, request):
                return generate_random_string(16)

        :param client: the client that makes the request.
        :param grant_type: the requested grant type.
        :param user: the authorized user.
        :param scope: the granted scope.
        :param request: the current request, or ``None``.
        """
        return generate_token(16)

    def access_token_generator(
        self, client, grant_type, user, scope, expires_in=None, request=None
    ):
        """Generate a JWT access token.

        :param client: the client that makes the request.
        :param grant_type: the requested grant type.
        :param user: the authorized user.
        :param scope: the granted scope.
        :param expires_in: the lifetime of the token, in seconds. Defaults to
            the lifetime of the grant type.
        :param request: the current request, or ``None``.
        """
        if expires_in is None:
            expires_in = self._get_expires_in(client, grant_type)

        now = int(time.time())
        token_data = {
            "iss": self.issuer,
            "exp": now + expires_in,
            "client_id": client.get_client_id(),
            "iat": now,
            "jti": self._call_hook(
                "get_jti", client, grant_type, user, scope, request=request
            ),
            "scope": scope,
        }

        # In cases of access tokens obtained through grants where a resource owner is
        # involved, such as the authorization code grant, the value of 'sub' SHOULD
        # correspond to the subject identifier of the resource owner.

        if user:
            token_data["sub"] = str(user.get_user_id())

        # In cases of access tokens obtained through grants where no resource owner is
        # involved, such as the client credentials grant, the value of 'sub' SHOULD
        # correspond to an identifier the authorization server uses to indicate the
        # client application.

        else:
            token_data["sub"] = client.get_client_id()

        # If the request includes a 'resource' parameter (as defined in [RFC8707]), the
        # resulting JWT access token 'aud' claim SHOULD have the same value as the
        # 'resource' parameter in the request.

        # TODO: Implement this with RFC8707
        if False:  # pragma: no cover
            ...

        # If the request does not include a 'resource' parameter, the authorization
        # server MUST use a default resource indicator in the 'aud' claim. If a 'scope'
        # parameter is present in the request, the authorization server SHOULD use it to
        # infer the value of the default resource indicator to be used in the 'aud'
        # claim. The mechanism through which scopes are associated with default resource
        # indicator values is outside the scope of this specification.

        else:
            token_data["aud"] = self._call_hook(
                "get_audiences", client, user, scope, request=request
            )

        # If the values in the 'scope' parameter refer to different default resource
        # indicator values, the authorization server SHOULD reject the request with
        # 'invalid_scope' as described in Section 4.1.2.1 of [RFC6749].
        # TODO: Implement this with RFC8707

        if auth_time := self._call_user_hook("get_auth_time", user, request):
            token_data["auth_time"] = auth_time

        # The meaning and processing of acr Claim Values is out of scope for this
        # specification.

        if acr := self._call_user_hook("get_acr", user, request):
            token_data["acr"] = acr

        # The definition of particular values to be used in the amr Claim is beyond the
        # scope of this specification.

        if amr := self._call_user_hook("get_amr", user, request):
            token_data["amr"] = amr

        # Authorization servers MAY return arbitrary attributes not defined in any
        # existing specification, as long as the corresponding claim names are collision
        # resistant or the access tokens are meant to be used only within a private
        # subsystem. Please refer to Sections 4.2 and 4.3 of [RFC7519] for details.

        token_data.update(
            self._call_hook(
                "get_extra_claims", client, grant_type, user, scope, request=request
            )
        )

        # This specification registers the 'application/at+jwt' media type, which can
        # be used to indicate that the content is a JWT access token. JWT access tokens
        # MUST include this media type in the 'typ' header parameter to explicitly
        # declare that the JWT represents an access token complying with this profile.
        # Per the definition of 'typ' in Section 4.1.9 of [RFC7515], it is RECOMMENDED
        # that the 'application/' prefix be omitted. Therefore, the 'typ' value used
        # SHOULD be 'at+jwt'.

        header = {"alg": self.alg, "typ": "at+jwt"}
        key = import_any_key(self.get_jwks())
        access_token = jwt.encode(
            header,
            token_data,
            key=key,
            algorithms=[self.alg],
        )
        return access_token

    def _call_user_hook(self, hook, user, request):
        """Call a hook with the request. A hook whose first parameter is not
        ``request`` gets the user, with a deprecation warning."""
        method = getattr(self, hook)
        if _takes_request(method):
            return method(request=request)

        self._warn_hook(
            hook,
            "receives the user. Make 'request' its only parameter. "
            "In 1.11, it will receive the request.",
        )
        return method(user)

    def _call_hook(self, hook, *args, request):
        """Call a hook with the request as a keyword argument. A hook without a
        ``request`` parameter is called without it, with a deprecation
        warning."""
        method = getattr(self, hook)
        if accepts_argument(method, "request"):
            return method(*args, request=request)

        self._warn_hook(
            hook,
            "does not accept a 'request' argument. In 1.11, it will always receive it.",
        )
        return method(*args)

    def _warn_hook(self, hook, message):
        """Warn once per hook that its signature is deprecated."""
        if hook in self._hooks_warned:
            return

        self._hooks_warned.add(hook)
        deprecate(f"'{type(self).__name__}.{hook}' {message}", stacklevel=5)


def _takes_request(method):
    """Tell whether the first parameter of a method is ``request``."""
    try:
        parameters = list(inspect.signature(method).parameters.values())
    except (TypeError, ValueError):
        return False

    return bool(parameters) and parameters[0].name == "request"
