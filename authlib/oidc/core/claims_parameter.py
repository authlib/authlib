"""The ``claims`` authorization request parameter of OpenID Connect Core 1.0.

https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
"""

import json

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidRequestError

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
    share. The extension does not check the ``acr`` and ``sub`` values that the
    parameter requests. To refuse an ``acr`` that the authentication does not
    satisfy, raise an error from the ``get_acr`` method of the authorization
    session.
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
