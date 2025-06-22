import base64
import os

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.integrations.django_oauth2 import AuthorizationServer
from tests.django_helper import TestCase as _TestCase

from .models import Client
from .models import OAuth2Token


class TestCase(_TestCase):
    def setUp(self):
        super().setUp()
        os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"

    def tearDown(self):
        super().tearDown()
        os.environ.pop("AUTHLIB_INSECURE_TRANSPORT")

    def create_server(self):
        return AuthorizationServer(Client, OAuth2Token)

    def create_basic_auth(self, username, password):
        text = f"{username}:{password}"
        auth = to_unicode(base64.b64encode(to_bytes(text)))
        return "Basic " + auth
