import json
import os
import time
from contextlib import contextmanager
from unittest import mock

import pytest
import requests

from authlib.integrations.base_client import InvalidIDTokenError

ROOT = os.path.abspath(os.path.dirname(__file__))


def read_key_file(name):
    file_path = os.path.join(ROOT, "keys", name)
    with open(file_path) as f:
        if name.endswith(".json"):
            return json.load(f)
        return f.read()


def mock_text_response(body, status_code=200):
    def fake_send(r, **kwargs):
        resp = mock.MagicMock(spec=requests.Response)
        resp.cookies = []
        resp.text = body
        resp.status_code = status_code
        return resp

    return fake_send


def mock_send_value(body, status_code=200):
    resp = mock.MagicMock(spec=requests.Response)
    resp.cookies = []
    if isinstance(body, dict):
        resp.json = lambda: body
    else:
        resp.text = body
    resp.status_code = status_code
    return resp


def get_bearer_token():
    return {
        "token_type": "Bearer",
        "access_token": "a",
        "refresh_token": "b",
        "expires_in": "3600",
        "expires_at": int(time.time()) + 3600,
    }


@contextmanager
def raises_id_token_error(cause):
    """Expect an InvalidIDTokenError caused by the given joserfc error."""
    with pytest.raises(InvalidIDTokenError) as exc_info:
        yield exc_info

    assert isinstance(exc_info.value.__cause__, cause)
    assert exc_info.value.error == exc_info.value.__cause__.error
