import re
import string

import pytest

from authlib.common.security import generate_pkce_code_verifier
from authlib.common.security import generate_token
from authlib.common.security import is_secure_transport

# RFC 7636 section 4.1: code-verifier = 43*128unreserved
# unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
CODE_VERIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9\-._~]{43,128}$")


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


def test_pkce_code_verifier_matches_rfc7636():
    """Regression for #935: the default PKCE code_verifier generator must
    produce values that match the RFC 7636 section 4.1 grammar (the same
    pattern the server side validates against in
    authlib.oauth2.rfc7636.challenge.CODE_VERIFIER_PATTERN), and should use
    the full unreserved character set rather than just alphanumerics.
    """
    verifiers = [generate_pkce_code_verifier() for _ in range(200)]

    for verifier in verifiers:
        assert CODE_VERIFIER_PATTERN.match(verifier), verifier
        assert len(verifier) == 128

    # every char used across many samples must be a subset of the allowed
    # unreserved characters, and the non-alphanumeric unreserved characters
    # must actually appear (not just be theoretically allowed)
    used_chars = set("".join(verifiers))
    assert used_chars <= set(string.ascii_letters + string.digits + "-._~")
    assert used_chars & set("-._~"), "expected at least one of -._~ across 200 samples"


@pytest.mark.parametrize("length", [0, 1, 42, 129, 200])
def test_pkce_code_verifier_rejects_out_of_range_length(length):
    with pytest.raises(ValueError):
        generate_pkce_code_verifier(length=length)


@pytest.mark.parametrize("length", [43, 64, 128])
def test_pkce_code_verifier_accepts_boundary_lengths(length):
    verifier = generate_pkce_code_verifier(length=length)
    assert CODE_VERIFIER_PATTERN.match(verifier)
    assert len(verifier) == length


def test_generate_token_default_charset_is_unaffected():
    """generate_token()'s own default (used for state, secrets, etc.
    elsewhere) must stay alphanumeric-only -- the PKCE fix must not widen
    it for unrelated callers.
    """
    token = generate_token(200)
    assert set(token) <= set(string.ascii_letters + string.digits)
