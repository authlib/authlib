import os

import pytest

from authlib.integrations.django_oauth1 import CacheAuthorizationServer

from .models import Client
from .models import TokenCredential
from .models import User

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def env():
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
    yield
    del os.environ["AUTHLIB_INSECURE_TRANSPORT"]


@pytest.fixture
def server(settings):
    """Create server that respects current settings."""
    return CacheAuthorizationServer(Client, TokenCredential)


@pytest.fixture
def plaintext_server(settings):
    """Server configured with PLAINTEXT signature method."""
    settings.AUTHLIB_OAUTH1_PROVIDER = {"signature_methods": ["PLAINTEXT"]}
    return CacheAuthorizationServer(Client, TokenCredential)


@pytest.fixture
def rsa_server(settings):
    """Server configured with RSA-SHA1 signature method."""
    settings.AUTHLIB_OAUTH1_PROVIDER = {"signature_methods": ["RSA-SHA1"]}
    return CacheAuthorizationServer(Client, TokenCredential)


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    user.save()
    yield user
    user.delete()


@pytest.fixture(autouse=True)
def client(user, db):
    client = Client(
        user_id=user.pk,
        client_id="client",
        client_secret="secret",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()
