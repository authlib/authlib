import base64
import binascii

from authlib.common.encoding import json_loads
from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.jose.errors import DecodeError
from authlib.jose.errors import ExceededSizeError


def extract_header(header_segment, error_cls):
    if len(header_segment) > 256000:
        raise ExceededSizeError(description="Value of header is too long")

    header_data = extract_segment(header_segment, error_cls, "header")

    try:
        header = json_loads(header_data.decode("utf-8"))
    except ValueError as e:
        raise error_cls(f"Invalid header string: {e}") from e

    if not isinstance(header, dict):
        raise error_cls("Header must be a json object")
    return header


def extract_segment(segment, error_cls, name="payload"):
    if len(segment) > 256000:
        raise ExceededSizeError(description=f"Value of {name} is too long")

    try:
        return _strict_urlsafe_b64decode(to_bytes(segment))
    except (TypeError, binascii.Error) as exc:
        msg = f"Invalid {name} encoding"
        raise error_cls(msg) from exc


_CANONICAL_ENDINGS = (b"AEIMQUYcgkosw048", b"AQgw")


def _strict_urlsafe_b64decode(s):
    """Decode base64url without padding, and refuse any other encoding of the
    same bytes, so that a token has a single serialization.
    """
    # Per RFC 7515 §2, base64url omits the padding characters.
    if b"=" in s or b"+" in s or b"/" in s:
        raise binascii.Error("Invalid base64url")

    pad = -len(s) % 4
    if pad == 3:
        raise binascii.Error("Invalid base64url length")

    # Per RFC 4648 §3.5, the pad bits are set to zero.
    if pad and s[-1] not in _CANONICAL_ENDINGS[pad - 1]:
        raise binascii.Error("Invalid base64url")

    return base64.b64decode(s + b"=" * pad, altchars=b"-_", validate=True)


def ensure_dict(s, structure_name):
    if not isinstance(s, dict):
        try:
            s = json_loads(to_unicode(s))
        except (ValueError, TypeError) as exc:
            raise DecodeError(f"Invalid {structure_name}") from exc

    if not isinstance(s, dict):
        raise DecodeError(f"Invalid {structure_name}")

    return s
