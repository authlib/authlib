import base64
import os
import unittest

from flask import Flask
from flask import request

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.sqla_oauth2 import create_query_client_func
from authlib.integrations.sqla_oauth2 import create_save_token_func
from authlib.oauth2 import OAuth2Error

from .models import Client
from .models import Token
from .models import User
from .models import db


def token_generator(client, grant_type, user=None, scope=None):
    token = f"{client.client_id[0]}-{grant_type}"
    if user:
        token = f"{token}.{user.get_user_id()}"
    return f"{token}.{generate_token(32)}"


def create_authorization_server(app, lazy=False):
    query_client = create_query_client_func(db.session, Client)
    save_token = create_save_token_func(db.session, Token)

    if lazy:
        server = AuthorizationServer()
        server.init_app(app, query_client, save_token)
    else:
        server = AuthorizationServer(app, query_client, save_token)

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        user_id = request.values.get("user_id")
        if user_id:
            end_user = db.session.get(User, int(user_id))
        else:
            end_user = None

        try:
            grant = server.get_consent_grant(end_user=end_user)
        except OAuth2Error as error:
            return server.handle_error_response(request, error)

        if request.method == "GET":
            return grant.prompt or "ok"

        return server.create_authorization_response(grant=grant, grant_user=end_user)

    @app.route("/oauth/token", methods=["GET", "POST"])
    def issue_token():
        return server.create_token_response()

    return server


def create_flask_app():
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = "testing"
    app.config.update(
        {
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "OAUTH2_ERROR_URIS": [("invalid_client", "https://a.b/e#invalid_client")],
        }
    )
    return app


class TestCase(unittest.TestCase):
    def setUp(self):
        os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
        app = create_flask_app()

        self._ctx = app.app_context()
        self._ctx.push()

        db.init_app(app)
        db.create_all()

        self.app = app
        self.client = app.test_client()

    def tearDown(self):
        db.drop_all()
        self._ctx.pop()
        os.environ.pop("AUTHLIB_INSECURE_TRANSPORT")

    def create_basic_header(self, username, password):
        text = f"{username}:{password}"
        auth = to_unicode(base64.b64encode(to_bytes(text)))
        return {"Authorization": "Basic " + auth}
