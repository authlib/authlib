from authlib.oauth2.rfc6749 import AuthorizationCodeMixin as _AuthorizationCodeMixin
from authlib.oauth2.rfc9470 import (
    AuthorizationSessionMixin as _AuthorizationSessionMixin,
)


class AuthorizationCodeMixin(_AuthorizationCodeMixin):
    def get_nonce(self):
        """Get "nonce" value of the authorization code object."""
        # OPs MUST support the prompt parameter, as defined in Section 3.1.2, including the specified user interface behaviors such as none and login.
        raise NotImplementedError()

    def get_auth_time(self):
        """Get "auth_time" value of the authorization code object."""
        # OPs MUST support returning the time at which the End-User authenticated via the auth_time Claim, when requested, as defined in Section 2.
        raise NotImplementedError()

    def get_acr(self) -> str | None:
        """Get the "acr" (Authentication Method Class) value of the authorization code object."""
        # OPs MUST support requests for specific Authentication Context Class Reference values via the acr_values parameter, as defined in Section 3.1.2. (Note that the minimum level of support required for this parameter is simply to have its use not result in an error.)
        return None

    def get_amr(self) -> list[str] | None:
        """Get the "amr" (Authentication Method Reference) value of the authorization code object.

        Have a look at :rfc:`RFC8176 <8176>` to see the full list of registered amr.

            def get_amr(self) -> list[str]:
                return ["pwd", "otp"]

        """
        return None

    def get_claims_request(self) -> dict | None:
        """Get the ``claims`` parameter of the authorization request, saved
        from ``request.claims_request``. The ``id_token`` member of this
        parameter gives the claims of the ID token. By default, there is none.
        See :class:`~authlib.oidc.core.ClaimsParameter`::

            def get_claims_request(self):
                return self.claims_request

        """
        return None


class AuthorizationSessionMixin(_AuthorizationSessionMixin):
    """The authorization session of OpenID Connect. It adds the account
    selection to :class:`~authlib.oauth2.rfc9470.AuthorizationSessionMixin`.

    The time of the ``"login"`` interaction becomes the ``auth_time`` claim of
    the ID token, and :meth:`get_acr` and :meth:`get_amr` give its ``acr`` and
    ``amr`` claims. The ``acr`` values that the client requests are given by
    :func:`~authlib.oidc.core.get_requested_acr_values`. To refuse a request
    whose requested ``acr`` cannot be met, raise
    :class:`~authlib.oidc.unmet_authentication_requirements.UnmetAuthenticationRequirementsError`
    from :meth:`get_acr`. :meth:`get_interaction_time` also takes
    ``"select_account"``, the time the user selected their account.
    """

    def is_account_selection_needed(self, request):
        """Tell if the user must select an account, for instance because
        several accounts are logged in. A client can still ask for it with
        ``prompt=select_account``. Either way, the selection is done when the
        user selects an account or logs in after the request started.

        :param request: the authorization request, with its ``user``
        """
        return False
