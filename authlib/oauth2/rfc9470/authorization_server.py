import time

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import InvalidRequestError


class StepUpAuthentication:
    """Authorization server extension for the authentication age of
    :rfc:`RFC9470 <9470>`. It applies the ``max_age`` parameter to the
    authorization requests::

        authorization_server.register_extension(StepUpAuthentication())

    It reads the time of the last login of the user from the
    :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin` passed to
    ``get_consent_grant``. When this login is older than ``max_age``,
    ``"login"`` is added to ``grant.interactions``, before the other
    interactions except ``"create"``.
    """

    def __call__(self, authorization_server):
        authorization_server.register_authorization_parameters(
            {"acr_values": str, "max_age": int}
        )
        authorization_server.register_hook(
            self.register_grant_hooks,
            after=AuthorizationServer.get_authorization_grant,
        )

    def register_grant_hooks(self, authorization_server, grant):
        """Validate ``max_age`` when the grant validates the request.

        :param authorization_server: the authorization server
        :param grant: the grant of the authorization request
        """
        grant.register_hook(self.validate_max_age, after=grant.validate_consent_request)

    def validate_max_age(self, grant, redirect_uri):
        """Add ``"login"`` to ``grant.interactions`` when the authentication of
        the user is older than ``max_age``.

        :param grant: the grant that validates the authorization request
        :param redirect_uri: the redirect URI of the authorization request
        :raises InvalidRequestError: if ``max_age`` is not a non-negative
            integer
        :raises ValueError: if there is no authorization session
        """
        max_age = get_max_age(
            grant.request, redirect_uri, grant.ERROR_RESPONSE_FRAGMENT
        )
        if max_age is None or "login" in grant.interactions:
            return

        session = grant.authorization_session
        if session is None:
            raise ValueError(
                "StepUpAuthentication needs an authorization session. "
                "Pass 'session' to 'get_consent_grant'."
            )

        if is_login_required(grant.request, session, max_age=max_age):
            index = 1 if grant.interactions[:1] == ["create"] else 0
            grant.interactions.insert(index, "login")


def is_login_required(request, session, max_age=None, fresh_login=False):
    """Tell if the user must log in, because the request asks for a new
    login or for a recent authentication.

    :param request: the authorization request, with its ``user`` and its
        ``request_time``
    :param session: the authorization session
    :param max_age: the maximum age of the authentication, in seconds
    :param fresh_login: whether the request asks for a new login, as with
        ``prompt=login``
    """
    # OIDC Core §3.1.2.1: max_age=0 is equivalent to prompt=login.
    fresh_login = fresh_login or max_age == 0
    if not fresh_login and max_age is None:
        return False

    if not request.user:
        return True

    if fresh_login:
        return not session.is_interaction_done(request, "login")

    auth_time = session.get_interaction_time(request, "login")
    if auth_time is None:
        return True

    request_time = request.request_time
    if request_time is None:
        request_time = time.time()

    return int(request_time) - int(auth_time) > max_age


def get_max_age(request, redirect_uri, redirect_fragment=False):
    """Return the ``max_age`` parameter of a request, or ``None``.

    :param request: the authorization request
    :param redirect_uri: the redirect URI of the authorization request
    :param redirect_fragment: whether errors are redirected in the fragment
    :raises InvalidRequestError: if ``max_age`` is not a non-negative integer
    """
    max_age = request.payload.data.get("max_age")
    # RFC 6749 §3.1: parameters sent without a value MUST be treated as if
    # they were omitted from the request.
    if max_age is None or max_age == "":
        return None

    if isinstance(max_age, str) and max_age.isascii() and max_age.isdigit():
        try:
            return int(max_age)
        except ValueError:
            pass

    elif isinstance(max_age, int) and not isinstance(max_age, bool) and max_age >= 0:
        return max_age

    raise InvalidRequestError(
        "Invalid 'max_age' parameter.",
        redirect_uri=redirect_uri,
        redirect_fragment=redirect_fragment,
    )
