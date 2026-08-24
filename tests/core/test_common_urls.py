import pytest

from authlib.common.urls import extract_params, is_valid_url


@pytest.mark.parametrize(
    "url",
    [
        "https://provider.test/cb",
        "https://provider.test:8443/cb",
        "http://provider.test/cb",
        "http://localhost:8080/cb",
        "https://provider.test/cb?next=user@provider.test",
        "https://provider.test/cb#fragment",
    ],
)
def test_valid_url(url):
    assert is_valid_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "",
        "provider.test/cb",
        "https://",
        "/cb",
        "urn:ietf:wg:oauth:2.0:oob",
    ],
)
def test_invalid_url(url):
    assert is_valid_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@provider.test/cb",
        "https://user@provider.test/cb",
        "https://@provider.test/cb",
        "https://provider.test@attacker.test/cb",
        "http://localhost:80@attacker.test/cb",
    ],
)
def test_userinfo_is_rejected(url):
    assert is_valid_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1]:80@attacker.test/cb",
        "http://[not-an-ip]/cb",
    ],
)
def test_unparsable_authority(url):
    """urlparse() raises ValueError on these, it must not propagate."""
    assert is_valid_url(url) is False


def test_fragments_not_allowed():
    assert is_valid_url("https://provider.test/cb", fragments_allowed=False) is True
    assert (
        is_valid_url("https://provider.test/cb#fragment", fragments_allowed=False)
        is False
    )


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("", id="string"),
        pytest.param({}, id="dict"),
        pytest.param([], id="list"),
        pytest.param((), id="tuple"),
    ],
)
def test_extract_params_empty(raw):
    """An empty input of any accepted kind means no parameters, not a failure."""
    assert extract_params(raw) == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("a=1&b=2", [("a", "1"), ("b", "2")], id="query-string"),
        pytest.param({"a": "1"}, [("a", "1")], id="dict"),
        pytest.param([("a", "1")], [("a", "1")], id="list-of-pairs"),
    ],
)
def test_extract_params(raw, expected):
    assert extract_params(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(None, id="none"),
        pytest.param(5, id="int"),
        pytest.param(object(), id="object"),
    ],
)
def test_extract_params_unsupported(raw):
    """Anything that is not a string, dict or sequence of pairs is rejected."""
    assert extract_params(raw) is None
