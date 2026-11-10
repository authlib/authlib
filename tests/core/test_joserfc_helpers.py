import pytest

from authlib._joserfc_helpers import audience_matches


@pytest.mark.parametrize(
    "aud,accepted,expected",
    [
        ("https://a.test", ["https://a.test"], True),
        (["https://b.test", "https://a.test"], ["https://a.test"], True),
        ("https://a.test", "https://a.test", True),
        ("https://b.test", ["https://a.test"], False),
        ([], ["https://a.test"], False),
        ("", "https://a.test", False),
        ("a.test", "https://a.test", False),
        ("https://a.test", [], False),
    ],
)
def test_audience_matches(aud, accepted, expected):
    """aud matches when it contains one of the accepted values."""
    assert audience_matches(aud, accepted) is expected
