import json
import os
from html.parser import HTMLParser

from authlib.common.encoding import to_unicode
from authlib.common.urls import url_decode

ROOT = os.path.abspath(os.path.dirname(__file__))

HMAC_SECRET = "a-test-hmac-secret-of-32-bytes!!"


def get_file_path(name):
    return os.path.join(ROOT, "files", name)


def read_file_path(name):
    with open(get_file_path(name)) as f:
        if name.endswith(".json"):
            return json.load(f)
        return f.read()


def decode_response(data):
    return dict(url_decode(to_unicode(data)))


class FormParser(HTMLParser):
    """Read the action and the hidden input values of a form_post response."""

    def __init__(self):
        super().__init__()
        self.action = None
        self.values = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs["action"]
        elif tag == "input":
            self.values[attrs["name"]] = attrs["value"]


def parse_form(body):
    parser = FormParser()
    parser.feed(body.decode())
    return parser
