import base64

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode


def create_basic_auth(username, password):
    text = f"{username}:{password}"
    auth = to_unicode(base64.b64encode(to_bytes(text)))
    return "Basic " + auth
