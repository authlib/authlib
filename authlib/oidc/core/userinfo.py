from joserfc import jwt
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import import_any_key
from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749.authorization_server import OAuth2Request
from authlib.oauth2.rfc6749.resource_protector import ResourceProtector
from authlib.oauth2.rfc6749.responses import JsonResponse
from authlib.oauth2.rfc6749.responses import OAuth2Response
from authlib.oauth2.rfc6750.errors import InvalidTokenError

from .claims import UserInfo


class UserInfoEndpoint:
    """OpenID Connect Core UserInfo Endpoint.

    This endpoint returns information about a given user, as a JSON payload or as a JWT.
    It must be subclassed and a few methods needs to be manually implemented::

        class UserInfoEndpoint(oidc.core.UserInfoEndpoint):
            def get_issuer(self):
                return "https://auth.example"

            def generate_user_info(self, user, scope):
                return UserInfo(
                    sub=user.id,
                    name=user.name,
                    ...
                ).filter(scope)

            def resolve_private_key(self):
                return server_private_jwk_set()

    It is also needed to pass a :class:`~authlib.oauth2.rfc6749.ResourceProtector` instance
    with a registered :class:`~authlib.oauth2.rfc6749.TokenValidator` at initialization,
    so the access to the endpoint can be restricter to valid token bearers::

        resource_protector = ResourceProtector()
        resource_protector.register_token_validator(BearerTokenValidator())
        server.register_endpoint(
            UserInfoEndpoint(resource_protector=resource_protector)
        )

    And then you can plug the endpoint to your application::

        @app.route("/oauth/userinfo", methods=["GET", "POST"])
        def userinfo():
            return server.create_endpoint_response("userinfo")

    Some clients send the access token in the request body instead of the
    ``Authorization`` header. To accept them, register
    :class:`~authlib.oauth2.rfc6750.FormEncodedBodyToken` on the resource
    protector::

        resource_protector.register_extension(FormEncodedBodyToken())

    """

    ENDPOINT_NAME = "userinfo"

    def __init__(
        self,
        server: AuthorizationServer | None = None,
        resource_protector: ResourceProtector | None = None,
    ):
        self.server = server
        self.resource_protector = resource_protector

    def create_endpoint_request(self, request: OAuth2Request):
        return self.server.create_oauth2_request(request)

    def __call__(self, request: OAuth2Request):
        token = self.resource_protector.acquire_token("openid")
        client = self.get_token_client(token)
        if client is None:
            raise InvalidTokenError()

        user = self.get_token_user(token)
        if user is None:
            raise InvalidTokenError()

        user_info = self.generate_user_info(user, token.get_scope())

        if alg := client.client_metadata.get("userinfo_signed_response_alg"):
            # If signed, the UserInfo Response MUST contain the Claims iss
            # (issuer) and aud (audience) as members. The iss value MUST be
            # the OP's Issuer Identifier URL. The aud value MUST be or
            # include the RP's Client ID value.
            user_info["iss"] = self.get_issuer()
            user_info["aud"] = client.client_id

            key = import_any_key(self.resolve_private_key())
            algorithms = self.get_supported_algorithms()
            data = jwt.encode({"alg": alg}, user_info, key, algorithms)
            return OAuth2Response(200, data, [("Content-Type", "application/jwt")])

        return JsonResponse(user_info)

    def get_token_client(self, token):
        """Return the client the access token was issued to.
        By default, it calls ``token.get_client()``.
        With :ref:`specs/rfc9068` JWT access tokens, developers must
        re-implement this method::

            def get_token_client(self, token):
                return self.server.query_client(token["client_id"])

        If it returns ``None``, the endpoint returns an ``invalid_token``
        error.

        :param token: The access token returned by the resource protector.
        """
        return token.get_client()

    def get_token_user(self, token):
        """Return the user the access token was issued for.
        By default, it calls ``token.get_user()``.
        With :ref:`specs/rfc9068` JWT access tokens, developers must
        re-implement this method::

            def get_token_user(self, token):
                return User.get(token["sub"])

        If it returns ``None``, for instance when the user was deleted, the
        endpoint returns an ``invalid_token`` error. JWT access tokens stay
        valid until they expire, so this is the way to deny access to a user.

        :param token: The access token returned by the resource protector.
        """
        return token.get_user()

    def get_supported_algorithms(self) -> list[str]:
        """Return the supported algorithms for userinfo signing.
        By default, it uses the recommended algorithms from ``joserfc``.
        Developer can override this method to customize the supported algorithms::

            def get_supported_algorithms(self) -> list[str]:
                return ["RS256"]
        """
        return JWSRegistry.recommended

    def generate_user_info(self, user, scope: str) -> UserInfo:
        """
        Generate a :class:`~authlib.oidc.core.UserInfo` object for an user::

            def generate_user_info(self, user, scope: str) -> UserInfo:
                return UserInfo(
                    given_name=user.given_name,
                    family_name=user.last_name,
                    email=user.email,
                    ...
                ).filter(scope)

        This method must be implemented by developers.
        """
        raise NotImplementedError()

    def get_issuer(self) -> str:
        """The OP's Issuer Identifier URL.

        The value is used to fill the ``iss`` claim that is mandatory in signed userinfo::

            def get_issuer(self) -> str:
                return "https://auth.example"

        This method must be implemented by developers to support JWT userinfo.
        """
        raise NotImplementedError()

    def resolve_private_key(self):
        """Return the server JSON Web Key Set.

        This is used to sign userinfo payloads::

            def resolve_private_key(self):
                return server_private_jwk_set()

        This method must be implemented by developers to support JWT userinfo signing.
        """
        return None  # pragma: no cover
