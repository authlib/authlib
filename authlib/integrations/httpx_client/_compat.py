"""Compatibility shim for httpx2 with legacy httpx fallback.

Falls back to httpx when httpx2 is unavailable. The fallback is deprecated
and will be removed in a future release.
"""

from authlib.deprecate import deprecate

try:
    import httpx2
except ImportError:
    import httpx as httpx2

    deprecate("The httpx module is deprecated; please use httpx2 instead.")

__all__ = ["httpx2"]
