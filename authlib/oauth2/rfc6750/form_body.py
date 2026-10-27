"""authlib.oauth2.rfc6750.form_body.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Form-Encoded Body Parameter per :rfc:`6750#section-2.2`.
"""

from ..rfc6749 import InvalidRequestError
from ..rfc6749 import MissingAuthorizationError


class FormEncodedBodyToken:
    """ResourceProtector extension that reads the access token from a
    form-encoded request body per :rfc:`6750#section-2.2`.

    The token is read only when the request has no ``Authorization`` header,
    a ``application/x-www-form-urlencoded`` body, and a method other than
    ``GET``. Requests that send the token both in the header and in the body
    are refused.

    Usage::

        from authlib.oauth2.rfc6750 import FormEncodedBodyToken

        require_oauth.register_extension(FormEncodedBodyToken())
    """

    def __call__(self, protector):
        protector.register_hook(
            "replace_parse_request_authorization", self._parse_request_authorization
        )

    def _parse_request_authorization(self, protector, original, request):
        """Return the validator and the token from the body, or call ``original``."""
        token_string = self._get_body_token(request)
        if token_string is None:
            return original(request)

        # https://www.rfc-editor.org/rfc/rfc6750#section-2
        # Clients MUST NOT use more than one method to transmit the token
        # in each request.
        if request.headers.get("Authorization"):
            raise InvalidRequestError(
                "The access token must be sent with only one method."
            )

        if not token_string:
            raise MissingAuthorizationError(
                protector._default_auth_type, protector._default_realm
            )

        validator = protector.get_token_validator("bearer")
        return validator, token_string

    def _get_body_token(self, request):
        """Return the access token sent in the request body, or None."""
        # https://www.rfc-editor.org/rfc/rfc6750#section-2.2
        # The HTTP request entity-header includes the "Content-Type" header
        # field set to "application/x-www-form-urlencoded".
        content_type = request.headers.get("Content-Type", "")
        if content_type.split(";")[0].strip().lower() != (
            "application/x-www-form-urlencoded"
        ):
            return None

        # https://www.rfc-editor.org/rfc/rfc6750#section-2.2
        # In particular, this means that the "GET" method MUST NOT be used.
        if request.method.upper() == "GET":
            return None

        try:
            form = request.form
        except (AttributeError, NotImplementedError):
            return None
        return form.get("access_token")
