"""Authorization server extension for Initiating User Registration via OpenID Connect 1.0.

https://openid.net/specs/openid-connect-prompt-create-1_0.html
"""

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oidc.core.grants.util import get_prompt_values
from authlib.oidc.core.grants.util import is_openid_scope


class PromptCreate:
    """Authorization server extension for the ``create`` value of ``prompt``.

    When the authorization request of an anonymous user contains
    ``prompt=create``, ``"create"`` is the first of ``grant.interactions``,
    before ``"login"``. The application can then show the account creation
    page instead of the login page::

        from authlib.oidc.prompt_create import PromptCreate

        authorization_server.register_extension(PromptCreate())

    For a logged-in user, ``create`` is ignored.
    """

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            self.register_grant_hooks,
            after=AuthorizationServer.get_authorization_grant,
        )

    def register_grant_hooks(self, authorization_server, grant):
        """Process the ``prompt`` parameter when the grant validates the
        request.

        :param authorization_server: The authorization server.
        :param grant: The grant of the authorization request.
        """
        grant.register_hook(self.process_prompt, after=grant.validate_consent_request)

    def process_prompt(self, grant, redirect_uri):
        """Add ``"create"`` first to ``grant.interactions`` when an anonymous
        user asks for it.

        :param grant: The grant that validates the authorization request.
        :param redirect_uri: The redirect URI of the authorization request.
        """
        if grant.request.user or not is_openid_scope(grant.request.payload.scope):
            return

        if "create" in get_prompt_values(grant.request):
            grant.interactions.insert(0, "create")
