import importlib
import sys

import pytest

from authlib.deprecate import AuthlibDeprecationWarning

MODULE = "authlib.integrations.httpx_client._compat"


def test_falls_back_to_httpx_with_deprecation_warning(monkeypatch):
    monkeypatch.setitem(sys.modules, "httpx2", None)
    sys.modules.pop(MODULE, None)

    with pytest.warns(AuthlibDeprecationWarning, match="httpx2"):
        compat = importlib.import_module(MODULE)

    import httpx

    assert compat.httpx2 is httpx

    sys.modules.pop(MODULE, None)


def test_uses_httpx2_without_warning(recwarn):
    sys.modules.pop(MODULE, None)

    compat = importlib.import_module(MODULE)

    import httpx2

    assert compat.httpx2 is httpx2
    assert not any(
        issubclass(w.category, AuthlibDeprecationWarning) for w in recwarn.list
    )
