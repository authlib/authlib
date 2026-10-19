import ipaddress
import os
import random
import string
from urllib.parse import urlsplit

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


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
