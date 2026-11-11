import time

from .rfc6749 import AuthorizationSessionMixin


class AuthorizationSession(AuthorizationSessionMixin):
    """An authorization session that keeps the start time of the
    authorization requests in the session of the web framework. Implement
    ``get_interaction_time``, and ``is_consent_needed`` if needed::

        from authlib.oauth2 import AuthorizationSession


        class MyAuthorizationSession(AuthorizationSession):
            def get_interaction_time(self, request, interaction):
                if interaction == "login":
                    return self.session.get("auth_time")
                return None


        # Flask
        authorization_session = MyAuthorizationSession(user, flask.session)
        # Django
        authorization_session = MyAuthorizationSession(user, request.session)

    Also implement ``get_acr`` and ``get_amr`` if needed, see
    :class:`~authlib.oauth2.rfc9470.AuthorizationSessionMixin`, and
    ``is_account_selection_needed`` with OpenID Connect, see
    :class:`~authlib.oidc.core.AuthorizationSessionMixin`. When the session
    is a signed cookie, read the pitfalls of :ref:`authorization_session`.

    :param user: the logged-in user, or ``None``
    :param session: the session of the web framework, as a mapping
    """

    #: The number of seconds a start time is kept. A longer time lets the
    #: user take more time to log in. A shorter time limits how long the same
    #: authorization request can be sent again without a new login.
    request_time_lifetime = 600

    #: The maximum number of start times in the session. The oldest ones are
    #: removed first. It keeps the session small.
    max_request_times = 5

    #: The session key of the start times.
    session_key = "authlib_request_times"

    def __init__(self, user, session):
        self.user = user
        self.session = session

    def get_user(self):
        """Return the user given to the constructor."""
        return self.user

    def get_request_time(self, request):
        """Return the start time of the authorization request. The first call
        for a request stores the current time in the session.

        :param request: the authorization request
        """
        key = request.authorization_key
        if key is None:
            return None

        stored = self.session.get(self.session_key) or {}
        now = int(time.time())
        recent = {
            other: start
            for other, start in stored.items()
            if now - start <= self.request_time_lifetime
        }
        start = recent.pop(key, now)
        others = sorted(recent.items(), key=lambda item: item[1], reverse=True)
        times = dict(others[: max(self.max_request_times - 1, 0)])
        times[key] = start
        if times != stored:
            self.session[self.session_key] = times

        return start

    def end_request(self, request):
        """Remove the start time of the authorization request from the
        session.

        :param request: the authorization request
        """
        stored = self.session.get(self.session_key) or {}
        if request.authorization_key not in stored:
            return

        times = dict(stored)
        del times[request.authorization_key]
        if times:
            self.session[self.session_key] = times
        else:
            del self.session[self.session_key]
