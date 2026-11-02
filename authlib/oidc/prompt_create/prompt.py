"""Authorization server extension for Initiating User Registration via OpenID Connect 1.0.

https://openid.net/specs/openid-connect-prompt-create-1_0.html
"""

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oidc.core.grants.util import is_openid_scope


class PromptCreate:
    """Authorization server extension for the ``create`` value of ``prompt``.

    When the authorization request contains ``prompt=create``, the grant
    ``prompt`` attribute is ``"create"``. The application can then show the
    account creation page instead of the login page::

        from authlib.oidc.prompt_create import PromptCreate

        authorization_server.register_extension(PromptCreate())

    ``create`` takes precedence over ``login``, ``consent`` and
    ``select_account``.
    """

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            self.process_prompt, after=AuthorizationServer.get_consent_grant
        )

    def process_prompt(self, authorization_server, grant):
        """Set the grant ``prompt`` to ``"create"`` when the request asks for it.

        :param authorization_server: The authorization server.
        :param grant: The grant returned by ``get_consent_grant``.
        """
        if not is_openid_scope(grant.request.payload.scope):
            return

        prompt = grant.request.payload.data.get("prompt")
        if prompt and "create" in prompt.split():
            grant.prompt = "create"
