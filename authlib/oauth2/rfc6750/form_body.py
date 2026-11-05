"""authlib.oauth2.rfc6750.form_body.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Form-Encoded Body Parameter per :rfc:`6750#section-2.2`.
"""

from ..rfc6749 import InvalidRequestError
from ..rfc6749 import ResourceProtector


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
            self._parse_request_authorization,
            replace=ResourceProtector.parse_request_authorization,
        )

    def _parse_request_authorization(self, protector, original, request):
        """Return the validator and the token from the body, or call ``original``."""
        token_string = self._get_body_token(request)
        if not token_string:
            return original(request)

        # Per RFC 6750 §2, clients MUST NOT use more than one method to
        # transmit the token in each request.
        if request.headers.get("Authorization"):
            raise InvalidRequestError(
                "The access token must be sent with only one method."
            )

        validator = protector.get_token_validator("bearer")
        return validator, token_string

    def _get_body_token(self, request):
        """Return the access token sent in the request body, or None."""
        # Per RFC 6750 §2.2, the "Content-Type" header field is set to
        # "application/x-www-form-urlencoded".
        content_type = request.headers.get("Content-Type", "")
        if content_type.split(";")[0].strip().lower() != (
            "application/x-www-form-urlencoded"
        ):
            return None

        # Per RFC 6750 §2.2, the "GET" method MUST NOT be used.
        if request.method.upper() == "GET":
            return None

        try:
            form = request.form
        except (AttributeError, NotImplementedError):
            return None

        return form.get("access_token")
