import os

import pytest
from flask import Flask


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
            "OAUTH1_SUPPORTED_SIGNATURE_METHODS": [
                "PLAINTEXT",
                "HMAC-SHA1",
                "RSA-SHA1",
            ],
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        }
    )

    with app.app_context():
        yield app


@pytest.fixture
def test_client(app, db):
    return app.test_client()


@pytest.fixture
def db(app):
    from .oauth1_server import db

    db.init_app(app)
    db.create_all()
    yield db
    db.drop_all()
