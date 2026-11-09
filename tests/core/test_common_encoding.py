import pytest

from authlib.common.encoding import json_loads


def test_json_loads_deeply_nested():
    with pytest.raises(ValueError, match="too deeply nested"):
        json_loads("[" * 1000000 + "]" * 1000000)
