from authlib.common.errors import AuthlibBaseError


class OAuthError(AuthlibBaseError):
    error = "oauth_error"


class MissingRequestTokenError(OAuthError):
    error = "missing_request_token"


class MissingTokenError(OAuthError):
    error = "missing_token"


class TokenExpiredError(OAuthError):
    error = "token_expired"


class InvalidTokenError(OAuthError):
    error = "token_invalid"


class UnsupportedTokenTypeError(OAuthError):
    error = "unsupported_token_type"


class MismatchingStateError(OAuthError):
    error = "mismatching_state"
    description = "CSRF Warning! State not equal in request and response."


class InvalidIDTokenError(OAuthError):
    """Raised when an ID token cannot be decoded or validated.

    The ``error`` and ``description`` attributes describe the failure, such as
    ``invalid_claim`` or ``expired_token``. The original error is available as
    ``__cause__``.
    """

    error = "invalid_id_token"
