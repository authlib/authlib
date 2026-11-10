import pytest

from authlib.oauth1.rfc5849.signature import normalize_base_string_uri


@pytest.mark.parametrize(
    "uri, expected",
    [
        # Default ports MUST be excluded (RFC 5849 section 3.4.1.2).
        ("http://example.com:80/r%20v/X?id=123", "http://example.com/r%20v/X"),
        ("https://www.example.net:443/?q=1", "https://www.example.net/"),
        # Default ports MUST also be excluded for IPv6 hosts, whose
        # bracketed address itself contains colons.
        ("http://[::1]:80/a", "http://[::1]/a"),
        ("https://[::1]:443/a", "https://[::1]/a"),
        ("http://[2001:db8::1]:80/a", "http://[2001:db8::1]/a"),
        # Non-default ports MUST be included.
        ("http://example.com:8080/a", "http://example.com:8080/a"),
        ("http://[::1]:8080/a", "http://[::1]:8080/a"),
        # No port at all: nothing to exclude, brackets stay intact.
        ("http://[::1]/a", "http://[::1]/a"),
        # Scheme and host MUST be lowercase.
        ("HTTP://EXAMPLE.COM/a", "http://example.com/a"),
        # An empty path becomes "/".
        ("http://example.com", "http://example.com/"),
    ],
)
def test_normalize_base_string_uri(uri, expected):
    assert normalize_base_string_uri(uri) == expected


def test_normalize_base_string_uri_uses_host_header():
    uri = "http://www.example.net:8080/?q=1"
    assert normalize_base_string_uri(uri, host="www.example.net:8080") == (
        "http://www.example.net:8080/"
    )
    assert normalize_base_string_uri(uri, host="www.example.net") == (
        "http://www.example.net/"
    )
    # An explicit IPv6 Host header with the default port is excluded too.
    assert normalize_base_string_uri("http://[::1]/a", host="[::1]:80") == (
        "http://[::1]/a"
    )


def test_normalize_base_string_uri_requires_scheme_and_netloc():
    with pytest.raises(ValueError):
        normalize_base_string_uri("/relative/path")
