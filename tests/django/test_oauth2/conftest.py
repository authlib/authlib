import os

import pytest

from authlib.integrations.django_oauth2 import AuthorizationServer

from .models import Client
from .models import OAuth2Token
from .models import User

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def env():
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
    yield
    os.environ.pop("AUTHLIB_INSECURE_TRANSPORT", None)


@pytest.fixture(autouse=True)
def server(settings):
    settings.AUTHLIB_OAUTH2_PROVIDER = {}
    return AuthorizationServer(Client, OAuth2Token)


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    user.set_password("ok")
    user.save()
    yield user
    user.delete()


@pytest.fixture
def token(user):
    token = OAuth2Token(
        user_id=user.pk,
        client_id="client-id",
        token_type="bearer",
        access_token="a1",
        refresh_token="r1",
        scope="profile",
        expires_in=3600,
    )
    token.save()
    yield token
    token.delete()
