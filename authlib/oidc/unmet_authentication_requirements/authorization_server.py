from authlib.common.hooks import Hookable
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oidc.core.grants.util import is_essential_acr_unmet
from authlib.oidc.core.grants.util import is_openid_scope

from .errors import UnmetAuthenticationRequirementsError


class UnmetAuthenticationRequirements:
    """Authorization server extension for OpenID Connect Core Error Code
    unmet_authentication_requirements::

        authorization_server.register_extension(UnmetAuthenticationRequirements())

    When the ``claims`` parameter requests an essential ``acr`` with values,
    and the ``acr`` that the authorization session returns is not one of them,
    the request is refused with ``unmet_authentication_requirements`` instead
    of ``access_denied``. Per this specification, the server SHALL use this
    error in this case. The error is redirected to the client.

    It needs :class:`~authlib.oidc.core.ClaimsParameter`, and an authorization
    session that inherits
    :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`. With the
    ``openid`` scope, ``get_acr`` of the session raises the error itself, also
    when the application calls it.
    """

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            self.register_grant_hooks,
            after=AuthorizationServer.get_authorization_grant,
        )

    def register_grant_hooks(self, authorization_server, grant):
        """Check the ``acr`` of the authorization session of the grant.

        :param authorization_server: The authorization server.
        :param grant: The grant of the authorization request.
        """
        grant.register_hook(
            self.register_session_hooks, before=grant.validate_consent_request
        )

    def register_session_hooks(self, grant):
        """Check the ``acr`` that ``get_acr`` returns, once the authorization
        session is attached to the grant. When ``get_acr`` cannot be hooked,
        for instance when a plain class defines it next to
        :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`, it is not
        checked, and the error stays ``access_denied``.

        :param grant: The grant of the authorization request.
        """
        session = grant.authorization_session
        if not isinstance(session, Hookable) or not hasattr(session, "get_acr"):
            return

        if not is_openid_scope(grant.request.payload.scope):
            return

        try:
            session.register_hook("replace_get_acr", self.validate_acr)
        except TypeError:
            return

    def validate_acr(self, session, get_acr, request):
        """Return the ``acr`` of the authorization session, or refuse an
        essential ``acr`` that it does not satisfy.

        :param session: The authorization session.
        :param get_acr: The ``get_acr`` method of the session.
        :param request: The authorization request.
        :raises UnmetAuthenticationRequirementsError: if the ``claims``
            parameter requests an essential ``acr`` that is not met
        """
        acr = get_acr(request)
        if is_essential_acr_unmet(request, acr):
            raise UnmetAuthenticationRequirementsError()

        return acr
