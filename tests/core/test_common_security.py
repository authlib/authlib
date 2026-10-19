import pytest

from authlib.common.security import is_secure_transport


@pytest.mark.parametrize(
    "uri",
    [
        "https://provider.test/cb",
        "https://provider.test:8443/cb",
        "HTTPS://PROVIDER.TEST/cb",
        "https://user:pass@provider.test/cb",
        # rfc8252 §7.3 loopback exemption, with and without an explicit port
        "http://localhost:8080/cb",
        "http://localhost/cb",
        "http://127.0.0.1:8080/cb",
        "http://127.0.0.1/cb",
        "http://[::1]:8080/cb",
        "http://[::1]/cb",
        # other spellings of the loopback interface
        "http://127.0.0.2:8080/cb",
        "http://[0:0:0:0:0:0:0:1]:8080/cb",
        "http://[::ffff:127.0.0.1]:8080/cb",
    ],
)
def test_secure_transport(uri):
    assert is_secure_transport(uri) is True


@pytest.mark.parametrize(
    "uri",
    [
        "http://provider.test/cb",
        "http://provider.test:8080/cb",
        # the loopback names are not a suffix match
        "http://localhost.provider.test/cb",
        "http://127.0.0.1.provider.test/cb",
        # 0.0.0.0 is unspecified, not loopback
        "http://0.0.0.0:8080/cb",
        # a mapped IPv4 address that is not loopback
        "http://[::ffff:93.184.216.34]:8080/cb",
        # not a transport at all
        "ftp://localhost:8080/cb",
        "urn:ietf:wg:oauth:2.0:oob",
        "javascript:alert(1)",
        "",
        "provider.test/cb",
        # no host to reason about
        "https://",
        "http://",
    ],
)
def test_insecure_transport(uri):
    assert is_secure_transport(uri) is False


@pytest.mark.parametrize(
    "uri",
    [
        "http://localhost:80@attacker.test/cb",
        "http://localhost:@attacker.test/cb",
        "http://localhost@attacker.test/cb",
        "http://127.0.0.1:80@attacker.test/cb",
        "http://127.0.0.1:@attacker.test/cb",
        # urlsplit() raises ValueError on this one, it must not propagate
        "http://[::1]:80@attacker.test/cb",
        "http://[::1]:@attacker.test/cb",
        # the loopback host is in the fragment, not in the authority
        "http://attacker.test#@localhost:80/cb",
        # unparsable authority
        "http://[not-an-ip]/cb",
    ],
)
def test_loopback_lookalike_authority(uri):
    """A loopback name outside of the host component must not pass the check."""
    assert is_secure_transport(uri) is False


def test_surrounding_whitespace_is_ignored():
    """urlsplit() strips whitespace and control characters before parsing."""
    assert is_secure_transport(" https://provider.test/cb ") is True
    assert is_secure_transport(" http://provider.test/cb ") is False


def test_insecure_transport_environment_variable(monkeypatch):
    monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "true")
    assert is_secure_transport("http://provider.test/cb") is True
