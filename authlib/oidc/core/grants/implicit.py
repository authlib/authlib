import logging

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.deprecate import deprecate
from authlib.oauth2.form_post import FormPost
from authlib.oauth2.rfc6749 import AccessDeniedError
from authlib.oauth2.rfc6749 import AuthorizationResponse
from authlib.oauth2.rfc6749 import ImplicitGrant
from authlib.oauth2.rfc6749 import InvalidScopeError
from authlib.oauth2.rfc6749 import OAuth2Error
from authlib.oauth2.rfc6749.errors import InvalidRequestError

from ._legacy import LegacyMixin
from .util import OPENID_AUTHORIZATION_PARAMETERS
from .util import create_half_hash
from .util import has_multiple_response_types
from .util import is_openid_scope
from .util import resolve_auth_time
from .util import set_silent
from .util import validate_nonce
from .util import validate_prompt_none
from .util import validate_request_prompt
from .util import validate_response_mode

log = logging.getLogger(__name__)


class OpenIDImplicitGrant(LegacyMixin, ImplicitGrant):
    RESPONSE_TYPES = {"id_token token", "id_token"}
    AUTHORIZATION_PARAMETERS = {
        **ImplicitGrant.AUTHORIZATION_PARAMETERS,
        **OPENID_AUTHORIZATION_PARAMETERS,
    }

    #: Deprecated. Use ``RESPONSE_MODE``.
    DEFAULT_RESPONSE_MODE = "fragment"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "DEFAULT_RESPONSE_MODE" in vars(cls) and "RESPONSE_MODE" not in vars(cls):
            deprecate(
                "'DEFAULT_RESPONSE_MODE' is deprecated. Use 'RESPONSE_MODE' instead.",
                version="1.11",
            )
            cls.RESPONSE_MODE = cls.DEFAULT_RESPONSE_MODE

    def exists_nonce(self, nonce, request):
        """Check if the given nonce was already used. Developers should
        implement this method in subclass. Per OpenID Connect Core §2, the
        authorization server should not process the nonce, so it can accept
        every nonce::

            def exists_nonce(self, nonce, request):
                return False

        :param nonce: A string of "nonce" parameter in request
        :param request: OAuth2Request instance
        :return: Boolean
        """
        raise NotImplementedError()

    def generate_user_info(self, user, scope):
        """Provide user information for the given scope. Developers
        MUST implement this method in subclass, e.g.::

            from authlib.oidc.core import UserInfo


            def generate_user_info(self, user, scope):
                user_info = UserInfo(sub=user.id, name=user.name)
                if "email" in scope:
                    user_info["email"] = user.email
                return user_info

        :param user: user instance
        :param scope: scope of the token
        :return: ``authlib.oidc.core.UserInfo`` instance
        """
        raise NotImplementedError()

    def validate_authorization_request(self):
        redirect_uri = super().validate_authorization_request()
        validate_response_mode(self, redirect_uri)
        if not is_openid_scope(self.request.scope):
            raise InvalidScopeError(
                "Missing 'openid' scope",
                redirect_uri=redirect_uri,
                redirect_fragment=True,
            )
        try:
            validate_nonce(self.request, self.exists_nonce, required=True)
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            error.redirect_fragment = True
            raise error
        return redirect_uri

    def validate_consent_request(self):
        set_silent(self)
        redirect_uri = self.validate_authorization_request()
        self.redirect_uri = redirect_uri
        validate_request_prompt(self, redirect_uri, redirect_fragment=True)
        return redirect_uri

    def validate_interactions(self):
        super().validate_interactions()
        validate_prompt_none(self, redirect_fragment=True)

    def create_authorization_response(self, redirect_uri, grant_user):
        if not grant_user:
            raise AccessDeniedError(redirect_uri=redirect_uri, redirect_fragment=True)

        self.request.user = grant_user
        self.request.auth_time = resolve_auth_time(self)
        params = self.create_granted_params(grant_user)
        if state := self.request.payload.state:
            params.append(("state", state))

        if has_multiple_response_types(self.server):
            response_mode = self.response_mode or self.RESPONSE_MODE
            return AuthorizationResponse(redirect_uri, params, response_mode)

        response_mode = self.request.payload.data.get(
            "response_mode", self.RESPONSE_MODE
        )
        response = AuthorizationResponse(redirect_uri, params, response_mode)
        if response_mode == "form_post":
            return FormPost().encode(response)

        return response

    def create_granted_params(self, grant_user):
        self.request.user = grant_user
        client = self.request.client
        token = self.generate_token(
            user=grant_user,
            scope=self.request.scope,
            include_refresh_token=False,
        )
        if self.request.payload.response_type == "id_token":
            token = {
                "expires_in": token["expires_in"],
                "scope": token["scope"],
            }
            token = self.process_implicit_token(token)
        else:
            log.debug("Grant token %r to %r", token, client)
            self.server.save_token(token, self.request)
            token = self.process_implicit_token(token)
        params = [(k, token[k]) for k in token]
        return params

    def process_implicit_token(self, token, code=None):
        alg = self.get_client_algorithm(self.request.client)
        if alg == "none":
            # According to oidc-registration §2 the 'none' alg is not valid in
            # implicit flows:
            #    The value none MUST NOT be used as the ID Token alg value unless
            #    the Client uses only Response Types that return no ID Token from
            #    the Authorization Endpoint (such as when only using the
            #    Authorization Code Flow).
            raise InvalidRequestError(
                "id_token must be signed in implicit flows",
                redirect_uri=self.request.payload.redirect_uri,
                redirect_fragment=True,
            )

        claims = self.get_compatible_claims(self.request)
        claims.pop("auth_time", None)
        if self.request.auth_time is not None:
            claims["auth_time"] = self.request.auth_time

        nonce = self.request.payload.data.get("nonce")
        if nonce:
            claims["nonce"] = nonce

        if code is not None:
            c_hash = create_half_hash(code, alg)
            if c_hash is not None:
                claims["c_hash"] = c_hash.decode("utf-8")

        access_token = token.get("access_token")
        if access_token:
            at_hash = create_half_hash(access_token, alg)
            if at_hash is not None:
                claims["at_hash"] = at_hash.decode("utf-8")

        user_info = self.generate_user_info(self.request.user, token["scope"])
        claims.update(user_info)
        key = self.resolve_client_private_key(self.request.client)
        private_key = import_any_key(key)
        header = self.get_encode_header(self.request.client)
        id_token = jwt.encode(header, claims, private_key, [alg])
        token["id_token"] = id_token
        return token
