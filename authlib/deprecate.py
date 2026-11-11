import inspect
import warnings


class AuthlibDeprecationWarning(DeprecationWarning):
    pass


warnings.simplefilter("always", AuthlibDeprecationWarning)


def deprecate(message, version=None, stacklevel=3):
    if version:
        message += f"\nIt will be compatible before version {version}."

    warnings.warn(AuthlibDeprecationWarning(message), stacklevel=stacklevel)


def accepts_argument(func, name):
    """Tell whether a function accepts a keyword argument."""
    try:
        parameters = inspect.signature(func).parameters.values()
    except (TypeError, ValueError):
        return False

    return any(
        parameter.name == name or parameter.kind == parameter.VAR_KEYWORD
        for parameter in parameters
    )
