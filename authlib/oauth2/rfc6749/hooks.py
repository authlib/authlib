from authlib.common.hooks import Hookable
from authlib.deprecate import deprecate

__all__ = ["Hookable", "hooked"]


def hooked(func=None, before=None, after=None, replace=None):
    """Deprecated. Methods of a :class:`Hookable` class run their hooks.

    This decorator does nothing and will be removed in version 1.11.

    :raises TypeError: If a custom hook name is passed.
    """
    deprecate(
        "'hooked' is deprecated. Methods of a Hookable class run their hooks.",
        version="1.11",
    )
    if before or after or replace:
        raise TypeError("'hooked' does not support custom hook names anymore.")

    if func is None:
        return lambda func: func

    return func
