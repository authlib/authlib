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


def deprecate_missing_arguments(description, func, names, stacklevel=4):
    """Warn when a function does not accept some keyword arguments."""
    if func is None:
        return

    missing = [name for name in names if not accepts_argument(func, name)]
    if not missing:
        return

    name = getattr(func, "__qualname__", None)
    arguments = ", ".join(f"'{argument}'" for argument in missing)
    deprecate(
        f"The {description} {name or func!r} does not accept these arguments: "
        f"{arguments}. In 1.11, it will always receive them.",
        stacklevel=stacklevel,
    )


def call_with_accepted_arguments(func, optional, /, **kwargs):
    """Call a function with keyword arguments. Leave out the ``optional``
    arguments that the function does not accept."""
    kwargs = {
        name: value
        for name, value in kwargs.items()
        if name not in optional or accepts_argument(func, name)
    }
    return func(**kwargs)
