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
from .util import get_auth_time_function
from .util import has_multiple_response_types
from .util import is_openid_scope
from .util import resolve_auth_time
from .util import validate_nonce
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

        if cls.get_auth_time is OpenIDImplicitGrant.get_auth_time and not (
            cls.__module__.startswith("authlib.")
        ):
            deprecate(
                "Not implementing 'get_auth_time' in the OpenID Connect implicit "
                "and hybrid grants is deprecated. Implement it to enforce the "
                "'max_age' parameter.",
                version="1.11",
            )

    def exists_nonce(self, nonce, request):
        """Check if the given nonce is existing in your database. Developers
        should implement this method in subclass, e.g.::

            def exists_nonce(self, nonce, request):
                exists = AuthorizationCode.query.filter_by(
                    client_id=request.payload.client_id, nonce=nonce
                ).first()
                return bool(exists)

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

    def get_auth_time(self, request):
        """Return the time of the last authentication of the user, as a Unix
        timestamp. Developers MUST implement this method in subclass. The
        value usually comes from the user session, e.g. with Django::

            def get_auth_time(self, request):
                return request.framework_request.session.get("auth_time")

        When the authentication is older than the ``max_age`` parameter,
        ``grant.prompt`` is ``"login"``. When it returns ``None``, the user
        must log in again. The value is also the ``auth_time`` claim of the
        ID token. When it is ``None``, the ID token has no ``auth_time``.
        In the hybrid flow, it is also ``request.auth_time`` in
        ``save_authorization_code``.

        :param request: the authorization request, with its ``user``
        :return: a timestamp, or ``None`` if it is unknown
        """
        raise NotImplementedError()

    def get_request_time(self, request):
        """Return the time the authorization request started, as a Unix
        timestamp. Developers MAY implement this method, along with
        ``get_auth_time``. Return the same time for all the HTTP requests of
        one authorization request, for instance before and after a login.
        ``request.authorization_key`` identifies the authorization request.
        Keep the time on the server side, and remove it when the request
        ends. The OpenID Connect guides of the Flask and Django integrations
        show how.

        With it, a login after this time satisfies ``prompt=login`` and
        ``max_age=0``, and ``max_age`` is measured from this time. Without
        it, these requests ask for a login each time, and ``max_age`` is
        measured from the current time.

        :param request: the authorization request
        :return: a timestamp, or ``None`` if it is unknown
        """
        return None

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
        redirect_uri = self.validate_authorization_request()
        validate_request_prompt(
            self,
            redirect_uri,
            redirect_fragment=True,
            get_auth_time=get_auth_time_function(self, OpenIDImplicitGrant),
            get_request_time=self.get_request_time,
        )
        return redirect_uri

    def create_authorization_response(self, redirect_uri, grant_user):
        if grant_user:
            self.request.user = grant_user
            self.request.auth_time = resolve_auth_time(
                self, OpenIDImplicitGrant, self.request
            )

        state = self.request.payload.state
        if grant_user:
            params = self.create_granted_params(grant_user)
            if state:
                params.append(("state", state))
        else:
            error = AccessDeniedError(state=state)
            params = error.get_body()

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
