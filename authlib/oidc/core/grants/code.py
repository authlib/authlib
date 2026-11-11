"""authlib.oidc.core.grants.code.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of Authentication using the Authorization Code Flow
per `Section 3.1`_.

.. _`Section 3.1`: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

import logging

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import OAuth2Response

from ..models import AuthorizationCodeMixin
from ._legacy import LegacyMixin
from .util import OPENID_AUTHORIZATION_PARAMETERS
from .util import call_generate_user_info
from .util import create_half_hash
from .util import get_requested_claims
from .util import is_openid_scope
from .util import is_requested_sub_unmet
from .util import resolve_auth_time
from .util import resolve_authentication
from .util import set_id_token_hint_sub
from .util import set_silent
from .util import validate_nonce
from .util import validate_prompt_none
from .util import validate_request_prompt
from .util import validate_requested_sub

log = logging.getLogger(__name__)


class OpenIDToken(LegacyMixin):
    def get_authorization_code_claims(self, authorization_code: AuthorizationCodeMixin):
        claims = {}
        if nonce := authorization_code.get_nonce():
            claims["nonce"] = nonce

        if (auth_time := authorization_code.get_auth_time()) is not None:
            claims["auth_time"] = auth_time

        if acr := authorization_code.get_acr():
            claims["acr"] = acr

        if amr := authorization_code.get_amr():
            claims["amr"] = amr
        return claims

    def generate_user_info(self, user, scope, claims):
        """Provide user information for the given scope. Developers
        MUST implement this method in subclass, e.g.::

            from authlib.oidc.core import UserInfo


            def generate_user_info(self, user, scope, claims):
                return UserInfo(sub=user.id, name=user.name, email=user.email).filter(
                    scope, claims
                )

        It is also called during the authorization request, to read the
        ``sub`` of the user, when the client asks for a specific user.

        :param user: user instance
        :param scope: scope of the token
        :param claims: the claims that the ``id_token`` member of the
            ``claims`` parameter requests, or ``None``. See
            :class:`~authlib.oidc.core.ClaimsParameter`.
        :return: ``authlib.oidc.core.UserInfo`` instance
        """
        raise NotImplementedError()

    def encode_id_token(self, token, request: OAuth2Request):
        alg = self.get_client_algorithm(request.client)
        header = self.get_encode_header(request.client)

        claims = self.get_compatible_claims(request)
        claims_request = None
        if request.authorization_code:
            claims.pop("auth_time", None)
            claims.update(
                self.get_authorization_code_claims(request.authorization_code)
            )
            get_claims_request = getattr(
                request.authorization_code, "get_claims_request", None
            )
            claims_request = get_claims_request() if get_claims_request else None

        access_token = token.get("access_token")
        if access_token:
            at_hash = create_half_hash(access_token, alg)
            if at_hash is not None:
                claims["at_hash"] = at_hash.decode("utf-8")

        user_info = call_generate_user_info(
            self.generate_user_info,
            request.user,
            token["scope"],
            get_requested_claims(claims_request, "id_token"),
        )
        claims.update(user_info)

        if alg == "none":
            private_key = None
        else:
            key = self.resolve_client_private_key(request.client)
            private_key = import_any_key(key)

        return jwt.encode(header, claims, private_key, [alg])

    def process_token(self, grant, response):
        if isinstance(response, OAuth2Response):
            token = response.body
        else:
            _, token, _ = response
        scope = token.get("scope")
        if not scope or not is_openid_scope(scope):
            # standard authorization code flow
            return token

        request: OAuth2Request = grant.request
        id_token = self.encode_id_token(token, request)
        token["id_token"] = id_token
        return token

    def __call__(self, grant):
        grant.register_hook(self.process_token, after=grant.create_token_response)


class OpenIDCode(OpenIDToken):
    """An extension from OpenID Connect for "grant_type=code" request. Developers
    MUST implement the missing methods::

        class MyOpenIDCode(OpenIDCode):
            def resolve_client_private_key(self, client):
                with open(jwks_file_path) as f:
                    data = json.load(f)
                return KeySet.import_key_set(data)

            def exists_nonce(self, nonce, request):
                return check_if_nonce_in_cache(request.payload.client_id, nonce)

            def generate_user_info(self, user, scope, claims):
                return {...}

    The register this extension with AuthorizationCodeGrant::

        authorization_server.register_grant(
            AuthorizationCodeGrant, extensions=[MyOpenIDCode()]
        )

    Also pass an :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`
    to ``get_consent_grant``. It gives the time of the user authentication.
    """

    def __init__(self, require_nonce=False):
        self.require_nonce = require_nonce

    def exists_nonce(self, nonce, request):
        """Check if the given nonce is existing in your database. Developers
        MUST implement this method in subclass, e.g.::

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

    def validate_openid_authorization_request(self, grant, redirect_uri):
        validate_nonce(grant.request, self.exists_nonce, self.require_nonce)
        set_id_token_hint_sub(grant.request, self)

    def set_request_authentication(self, grant, redirect_uri, grant_user):
        """Set ``request.auth_time``, ``request.acr`` and ``request.amr`` from
        the authorization session, so that ``save_authorization_code`` can
        store them. They become the ``auth_time``, ``acr`` and ``amr`` claims
        of the ID token. Without the ``openid`` scope, ``acr`` and ``amr`` are
        ``None``.

        :param grant: the grant that creates the authorization response
        :param redirect_uri: the redirect URI of the authorization request
        :param grant_user: the user who grants the request, or ``None``
        """
        grant.request.acr = None
        grant.request.amr = None
        if not grant_user:
            grant.request.auth_time = None
            return

        grant.request.user = grant_user
        if not is_openid_scope(grant.request.payload.scope):
            grant.request.auth_time = resolve_auth_time(grant)
            return

        validate_requested_sub(grant, self, redirect_uri)
        resolve_authentication(grant, redirect_uri)

    def validate_openid_prompt(self, grant, redirect_uri):
        """Validate the ``prompt`` and ``max_age`` parameters of the request.
        The user must also log in when the request asks for another user,
        with ``id_token_hint`` or with the ``sub`` claim of the ``claims``
        parameter.

        :param grant: the grant that validates the authorization request
        :param redirect_uri: the redirect URI of the authorization request
        """
        grant.redirect_uri = redirect_uri
        validate_request_prompt(
            grant,
            redirect_uri,
            other_user=is_requested_sub_unmet(grant.request, self),
        )

    def validate_openid_interactions(self, grant, result):
        """Return an error when ``prompt`` is ``none`` and the user must go
        through an interaction.

        :param grant: the grant that validates the authorization request
        :param result: the result of ``validate_interactions``
        """
        validate_prompt_none(grant)

    def __call__(self, grant):
        grant.register_hook(self.process_token, after=grant.create_token_response)
        grant.register_hook(
            self.set_request_authentication,
            before=grant.create_authorization_response,
        )
        if is_openid_scope(grant.request.payload.scope):
            grant.register_authorization_parameters(OPENID_AUTHORIZATION_PARAMETERS)
            grant.register_hook(
                self.validate_openid_authorization_request,
                after=grant.validate_authorization_request_payload,
            )
            grant.register_hook(set_silent, before=grant.validate_consent_request)
            grant.register_hook(
                self.validate_openid_prompt,
                after=grant.validate_consent_request,
            )
            grant.register_hook(
                self.validate_openid_interactions,
                after=grant.validate_interactions,
            )
