from ..rfc6749 import AuthorizationSessionMixin as _AuthorizationSessionMixin


class AuthorizationSessionMixin(_AuthorizationSessionMixin):
    """The authorization session of :rfc:`RFC9470 <9470>`. It adds the
    authentication context of the user, ``acr`` and ``amr``, to
    :class:`~authlib.oauth2.rfc6749.AuthorizationSessionMixin`.
    """

    def get_acr(self, request):
        """Return the Authentication Context Class Reference that the
        authentication of the user satisfies, such as
        ``"urn:mace:incommon:iap:silver"``. The values that the client
        requests are given by
        :func:`~authlib.oauth2.rfc9470.get_requested_acr_values`. Raise an
        :class:`~authlib.oauth2.OAuth2Error` to refuse the request: it is
        redirected to the client. By default, there is no ``acr``.

        :param request: the authorization request, with its ``user``
        """
        return None

    def get_amr(self):
        """Return the list of the Authentication Method References of the
        authentication of the user, such as ``["pwd", "otp"]``
        (:rfc:`8176`). By default, there is no ``amr``.
        """
        return None
