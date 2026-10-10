from importlib import import_module
from typing import TYPE_CHECKING

__all__ = [
    "base_client",
    "django_client",
    "django_oauth1",
    "django_oauth2",
    "flask_client",
    "flask_oauth1",
    "flask_oauth2",
    "httpx_client",
    "requests_client",
    "sqla_oauth2",
    "starlette_client",
]


if TYPE_CHECKING:
    from . import base_client
    from . import django_client
    from . import django_oauth1
    from . import django_oauth2
    from . import flask_client
    from . import flask_oauth1
    from . import flask_oauth2
    from . import httpx_client
    from . import requests_client
    from . import sqla_oauth2
    from . import starlette_client


def __getattr__(name):
    if name in __all__:
        return import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
