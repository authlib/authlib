import os

import pytest
from flask import Flask

from authlib.jose import jwt
from tests.flask.test_oauth2.oauth2_server import create_authorization_server
from tests.util import read_file_path

from .models import Client
from .models import Token
from .models import User


@pytest.fixture(autouse=True)
def env():
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
    yield
    del os.environ["AUTHLIB_INSECURE_TRANSPORT"]


@pytest.fixture
def app():
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = "testing"
    app.config.update(
        {
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "OAUTH2_ERROR_URIS": [
                ("invalid_client", "https://client.test/error#invalid_client")
            ],
        }
    )
    with app.app_context():
        yield app


@pytest.fixture
def db(app):
    from .models import db

    db.init_app(app)
    db.create_all()
    yield db
    db.drop_all()


@pytest.fixture
def test_client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)


@pytest.fixture
def client(db, user):
    client = Client(
        user_id=user.id,
        client_id="client-id",
        client_secret="client-secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


@pytest.fixture
def server(app):
    return create_authorization_server(app)


@pytest.fixture
def token(db):
    token = Token(
        user_id=1,
        client_id="client-id",
        token_type="bearer",
        access_token="a1",
        refresh_token="r1",
        scope="profile",
        expires_in=3600,
    )
    db.session.add(token)
    db.session.commit()
    yield token
    db.session.delete(token)


def create_id_token(claims):
    """Create a signed ID token for testing."""
    priv_key = read_file_path("jwks_private.json")
    header = {"alg": "RS256"}
    token = jwt.encode(header, claims, priv_key)
    return token.decode("utf-8")


@pytest.fixture
def id_token():
    """Create a valid ID token for testing."""
    return create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )


@pytest.fixture
def id_token_wrong_issuer():
    """Create an ID token with wrong issuer."""
    return create_id_token(
        {
            "iss": "https://other-provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )
