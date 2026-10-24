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
    """Raised when an ID token can not be decoded or validated.

    Since Authlib 1.7, ID tokens are validated with :mod:`joserfc`. This error
    keeps ID token failures inside the :class:`AuthlibBaseError` hierarchy.
    Instances raised by :meth:`OpenIDMixin.parse_id_token` are also instances
    of the original :mod:`joserfc` exception class, so ``except`` clauses that
    catch :mod:`joserfc` errors keep working. The original exception is
    available as ``__cause__``.
    """

    error = "invalid_id_token"


_invalid_id_token_error_classes = {}


def wrap_id_token_error(error):
    """Convert a :mod:`joserfc` error into an :class:`InvalidIDTokenError`.

    The returned exception is an instance of both :class:`InvalidIDTokenError`
    and the class of ``error``, with the same ``error`` and ``description``.
    """
    jose_cls = type(error)
    cls = _invalid_id_token_error_classes.get(jose_cls)
    if cls is None:
        cls = type(
            f"InvalidIDToken{jose_cls.__name__}",
            (InvalidIDTokenError, jose_cls),
            {"__module__": __name__},
        )
        _invalid_id_token_error_classes[jose_cls] = cls

    # Both parent classes define ``__init__`` and chain to ``super()``, so the
    # attributes are copied directly instead of calling either of them.
    wrapped = cls.__new__(cls)
    wrapped.__dict__.update(error.__dict__)
    wrapped.error = error.error
    wrapped.description = error.description
    Exception.__init__(wrapped, *error.args)
    return wrapped
