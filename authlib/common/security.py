import ipaddress
import os
import random
import string
from urllib.parse import urlsplit

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits

#: RFC 7636 section 4.1 unreserved characters:
#: ``ALPHA / DIGIT / "-" / "." / "_" / "~"``.
PKCE_CODE_VERIFIER_CHARACTER_SET = UNICODE_ASCII_CHARACTER_SET + "-._~"


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


def generate_pkce_code_verifier(length=128):
    """Generate a PKCE ``code_verifier`` per RFC 7636 section 4.1: the
    character set is ``ALPHA / DIGIT / "-" / "." / "_" / "~"`` and length
    must be 43-128 characters. Defaults to the maximum length for the
    largest practical entropy margin.
    """
    if not 43 <= length <= 128:
        raise ValueError(
            "RFC 7636 requires a code_verifier length between 43 and 128 "
            f"characters, got {length}"
        )
    return generate_token(length, PKCE_CODE_VERIFIER_CHARACTER_SET)


def is_secure_transport(uri):
    """Check if the uri is over ssl."""
    if os.getenv("AUTHLIB_INSECURE_TRANSPORT"):
        return True

    try:
        parts = urlsplit(uri)
    except ValueError:
        return False

    if not parts.hostname:
        return False

    if parts.scheme == "https":
        return True

    if parts.scheme != "http":
        return False

    # rfc8252 §7.3: native apps may use http for loopback redirection URIs.
    if parts.hostname == "localhost":
        return True

    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError:
        return False

    # IPv6Address.is_loopback only accounts for the mapped IPv4 address since
    # CPython 3.10.16, 3.11.11 and 3.12.4.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    return address.is_loopback
