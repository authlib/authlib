import json
import os

from authlib.common.encoding import to_unicode
from authlib.common.urls import url_decode

ROOT = os.path.abspath(os.path.dirname(__file__))


def get_file_path(name):
    return os.path.join(ROOT, "files", name)


def read_file_path(name):
    with open(get_file_path(name)) as f:
        if name.endswith(".json"):
            return json.load(f)
        return f.read()


def decode_response(data):
    return dict(url_decode(to_unicode(data)))
