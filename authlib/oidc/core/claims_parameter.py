"""The ``claims`` authorization request parameter of OpenID Connect Core 1.0.

https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
"""

import json

from authlib.oauth2 import rfc9470
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidRequestError

from .grants.util import get_claims_parameter_acr_values
from .grants.util import get_requested_subs
from .grants.util import is_openid_scope

# OIDC Core §5.5: the members that request claims for the ID token and for the
# UserInfo endpoint.
_CLAIMS_REQUEST_MEMBERS = ("userinfo", "id_token")


class ClaimsParameter:
    """Authorization server extension for the ``claims`` parameter of
    OpenID Connect Core 1.0 §5.5. With this parameter, a client requests
    individual claims for the ID token and for the UserInfo endpoint::

        from authlib.oidc.core import ClaimsParameter

        authorization_server.register_extension(ClaimsParameter())

    Also publish ``"claims_parameter_supported": true`` in the server
    metadata. Without this extension, the parameter is ignored.

    The parameter of an ``openid`` request is in ``request.claims_request``,
    as a dict. Save it with the authorization code and with the tokens. The
    ``generate_user_info`` methods receive the claims of their target in their
    ``claims`` argument: the ``id_token`` member for the ID token, and the
    ``userinfo`` member for the UserInfo endpoint.

    The parameter can request claims that the scope does not cover. Show them
    on the consent page, and only return the claims that the user accepts to
    share.

    When the parameter requests an essential ``acr`` with ``values``, and the
    ``acr`` that ``get_acr`` returns is not one of them, the request is refused
    with ``access_denied``. To return ``unmet_authentication_requirements``
    instead, register
    :class:`~authlib.oidc.unmet_authentication_requirements.UnmetAuthenticationRequirements`.

    When the parameter asks for a ``sub`` value, the user must be this user.
    See :func:`get_requested_sub`.
    """

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            self.register_grant_hooks,
            after=AuthorizationServer.get_authorization_grant,
        )

    def register_grant_hooks(self, authorization_server, grant):
        """Read the ``claims`` parameter when the grant validates the request.

        :param authorization_server: The authorization server.
        :param grant: The grant of the authorization request.
        """
        grant.register_hook(
            self.validate_claims_parameter, after=grant.validate_authorization_request
        )

    def validate_claims_parameter(self, grant, redirect_uri):
        """Set ``request.claims_request`` from the ``claims`` parameter of an
        ``openid`` request, or to ``None``.

        Per OIDC Core §5.5, the value is a JSON object. Its ``userinfo`` and
        ``id_token`` members are JSON objects. Other members, and the content
        of these members, are kept as they are, so that extensions such as
        OpenID Connect for Identity Assurance can read them.

        :param grant: The grant that validates the authorization request.
        :param redirect_uri: The redirect URI of the authorization request.
        :raises InvalidRequestError: if the parameter is not a valid JSON
            object, redirected to the client
        """
        request = grant.request
        request.claims_request = None
        if not is_openid_scope(request.payload.scope):
            return

        value = request.payload.data.get("claims")
        # RFC 6749 §3.1: parameters sent without a value MUST be treated as if
        # they were omitted from the request.
        if value is None or value == "":
            return

        claims_request = _parse_claims_request(value)
        if claims_request is None:
            raise InvalidRequestError(
                "Invalid 'claims' parameter.",
                redirect_uri=redirect_uri,
                redirect_fragment=grant.ERROR_RESPONSE_FRAGMENT,
            )

        request.claims_request = claims_request


def get_requested_acr_values(request):
    """Return the ``acr`` values that the request asks for, in order of
    preference, or an empty list. The values of the ``acr`` claim in the
    ``id_token`` member of the ``claims`` parameter come first. Without them,
    the values of the ``acr_values`` parameter are returned.

    :param request: the authorization request
    """
    values = get_claims_parameter_acr_values(getattr(request, "claims_request", None))
    if values is not None:
        return values

    return rfc9470.get_requested_acr_values(request)


def get_requested_sub(request):
    """Return the ``sub`` of the user that the request asks for, or ``None``.
    The value of the ``sub`` claim in the ``id_token`` member of the
    ``claims`` parameter comes first. Without it, the ``sub`` of the
    ``id_token_hint`` parameter is returned.

    The OpenID Connect grants validate ``id_token_hint`` with the request.
    When the user is another user, ``"login"`` is in ``grant.interactions``.
    If the user who logs in is still another user, the request is refused with
    ``login_required``. When the two values differ, no user can meet the
    request.

    :param request: the authorization request
    """
    subs = get_requested_subs(request)
    return subs[0] if subs else None


def _parse_claims_request(value):
    """Return the claims parameter as a dict, or None if it is invalid. A
    request object gives it as a dict, and a query parameter as a JSON
    string."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            return None

    if not isinstance(value, dict):
        return None

    for member in _CLAIMS_REQUEST_MEMBERS:
        if member in value and not isinstance(value[member], dict):
            return None

    return value
