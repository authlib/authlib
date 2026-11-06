"""Authorization server extension for Initiating User Registration via OpenID Connect 1.0.

https://openid.net/specs/openid-connect-prompt-create-1_0.html
"""

from authlib.oauth2.base import invalid_error_characters
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc8414.models import validate_array_value
from authlib.oidc.core.grants.util import get_prompt_values
from authlib.oidc.core.grants.util import is_openid_scope


class PromptValues:
    """Authorization server extension for the ``prompt_values_supported``
    server metadata of Initiating User Registration via OpenID Connect 1.0.
    Declare the supported values in :meth:`get_server_metadata`::

        from authlib.oidc.prompt_create import PromptValues


        class SupportedPromptValues(PromptValues):
            def get_server_metadata(self):
                return {
                    "prompt_values_supported": [
                        "none",
                        "login",
                        "consent",
                        "select_account",
                        "create",
                    ]
                }


        authorization_server.register_extension(SupportedPromptValues())

    The requests with another ``prompt`` value get an HTTP 400
    ``invalid_request`` error. When the list contains ``create`` and an
    anonymous user asks for it, ``"create"`` is the first of
    ``grant.interactions``, before ``"login"``. The application can then show
    the account creation page instead of the login page. For a logged-in
    user, ``create`` is ignored.

    Without ``prompt_values_supported``, the extension does nothing.
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
        grant.register_hook(
            self.validate_prompt_values, after=grant.validate_authorization_request
        )
        grant.register_hook(self.process_prompt, after=grant.validate_consent_request)

    def get_server_metadata(self):
        """Return the server metadata, with the ``prompt_values_supported``
        list. It is called during each authorization request, so it can read
        the configuration of the application. An invalid list raises an error
        on each request.

        :return: a dict of server metadata
        """
        return {}

    def get_supported_values(self):
        """Return the ``prompt_values_supported`` server metadata, or
        ``None``.

        :raises ValueError: if ``prompt_values_supported`` is not a list of
            strings
        """
        metadata = self.get_server_metadata()
        values = metadata.get("prompt_values_supported")
        if values is None:
            return None

        validate_array_value(metadata, "prompt_values_supported")
        if not all(isinstance(value, str) for value in values):
            raise ValueError('"prompt_values_supported" MUST contain strings')

        return values

    def validate_prompt_values(self, grant, redirect_uri):
        """Reject the ``prompt`` values that are not in the
        ``prompt_values_supported`` server metadata. It runs once the client
        and the redirect URI are valid, before the other ``prompt`` rules.

        Per Initiating User Registration via OpenID Connect 1.0 §4.1, the
        server SHOULD respond with an HTTP 400 status code and an
        ``invalid_request`` error. The user is not redirected to the client.
        It is RECOMMENDED that the error description identifies the value.

        :param grant: The grant that validates the authorization request.
        :param redirect_uri: The redirect URI of the authorization request.
        :raises InvalidRequestError: if a ``prompt`` value is not supported
        :raises ValueError: if ``prompt_values_supported`` is not a list of
            strings
        """
        if not is_openid_scope(grant.request.payload.scope):
            return

        supported = self.get_supported_values()
        if supported is None:
            return

        for value in get_prompt_values(grant.request):
            if value in supported:
                continue

            if invalid_error_characters(value):
                raise InvalidRequestError(
                    "The 'prompt' parameter contains an unsupported value."
                )

            raise InvalidRequestError(f"The 'prompt' value '{value}' is not supported.")

    def process_prompt(self, grant, redirect_uri):
        """Add ``"create"`` first to ``grant.interactions`` when an anonymous
        user asks for it, and ``prompt_values_supported`` contains it.

        :param grant: The grant that validates the authorization request.
        :param redirect_uri: The redirect URI of the authorization request.
        """
        if grant.request.user or not is_openid_scope(grant.request.payload.scope):
            return

        supported = self.get_supported_values() or []
        if "create" in supported and "create" in get_prompt_values(grant.request):
            grant.interactions.insert(0, "create")
