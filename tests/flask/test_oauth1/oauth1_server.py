import os
import unittest

from flask import Flask
from flask import jsonify
from flask import request
from flask_sqlalchemy import SQLAlchemy

from authlib.common.urls import url_encode
from authlib.integrations.flask_oauth1 import AuthorizationServer
from authlib.integrations.flask_oauth1 import ResourceProtector
from authlib.integrations.flask_oauth1 import (
    create_exists_nonce_func as create_cache_exists_nonce_func,
)
from authlib.integrations.flask_oauth1 import current_credential
from authlib.integrations.flask_oauth1 import register_nonce_hooks
from authlib.integrations.flask_oauth1 import register_temporary_credential_hooks
from authlib.oauth1 import ClientMixin
from authlib.oauth1 import TemporaryCredentialMixin
from authlib.oauth1 import TokenCredentialMixin
from authlib.oauth1.errors import OAuth1Error
from tests.util import read_file_path

from ..cache import SimpleCache

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)

    def get_user_id(self):
        return self.id


class Client(ClientMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(48), index=True)
    client_secret = db.Column(db.String(120), nullable=False)
    default_redirect_uri = db.Column(db.Text, nullable=False, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def get_client_secret(self):
        return self.client_secret

    def get_rsa_public_key(self):
        return read_file_path("rsa_public.pem")


class TokenCredential(TokenCredentialMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")
    client_id = db.Column(db.String(48), index=True)
    oauth_token = db.Column(db.String(84), unique=True, index=True)
    oauth_token_secret = db.Column(db.String(84))

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret


class TemporaryCredential(TemporaryCredentialMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")
    client_id = db.Column(db.String(48), index=True)
    oauth_token = db.Column(db.String(84), unique=True, index=True)
    oauth_token_secret = db.Column(db.String(84))
    oauth_verifier = db.Column(db.String(84))
    oauth_callback = db.Column(db.Text, default="")

    def get_user_id(self):
        return self.user_id

    def get_client_id(self):
        return self.client_id

    def get_redirect_uri(self):
        return self.oauth_callback

    def check_verifier(self, verifier):
        return self.oauth_verifier == verifier

    def get_oauth_token(self):
        return self.oauth_token

    def get_oauth_token_secret(self):
        return self.oauth_token_secret


class TimestampNonce(db.Model):
    __table_args__ = (
        db.UniqueConstraint(
            "client_id", "timestamp", "nonce", "oauth_token", name="unique_nonce"
        ),
    )
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(48), nullable=False)
    timestamp = db.Column(db.Integer, nullable=False)
    nonce = db.Column(db.String(48), nullable=False)
    oauth_token = db.Column(db.String(84))


def exists_nonce(nonce, timestamp, client_id, oauth_token):
    q = TimestampNonce.query.filter_by(
        nonce=nonce,
        timestamp=timestamp,
        client_id=client_id,
    )
    if oauth_token:
        q = q.filter_by(oauth_token=oauth_token)
    rv = q.first()
    if rv:
        return True

    item = TimestampNonce(
        nonce=nonce,
        timestamp=timestamp,
        client_id=client_id,
        oauth_token=oauth_token,
    )
    db.session.add(item)
    db.session.commit()
    return False


def create_temporary_credential(token, client_id, redirect_uri):
    item = TemporaryCredential(
        client_id=client_id,
        oauth_token=token["oauth_token"],
        oauth_token_secret=token["oauth_token_secret"],
        oauth_callback=redirect_uri,
    )
    db.session.add(item)
    db.session.commit()
    return item


def get_temporary_credential(oauth_token):
    return TemporaryCredential.query.filter_by(oauth_token=oauth_token).first()


def delete_temporary_credential(oauth_token):
    q = TemporaryCredential.query.filter_by(oauth_token=oauth_token)
    q.delete(synchronize_session=False)
    db.session.commit()


def create_authorization_verifier(credential, grant_user, verifier):
    credential.user_id = grant_user.id  # assuming your end user model has `.id`
    credential.oauth_verifier = verifier
    db.session.add(credential)
    db.session.commit()
    return credential


def create_token_credential(token, temporary_credential):
    credential = TokenCredential(
        oauth_token=token["oauth_token"],
        oauth_token_secret=token["oauth_token_secret"],
        client_id=temporary_credential.get_client_id(),
    )
    credential.user_id = temporary_credential.get_user_id()
    db.session.add(credential)
    db.session.commit()
    return credential


def create_authorization_server(app, use_cache=False, lazy=False):
    def query_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    if lazy:
        server = AuthorizationServer()
        server.init_app(app, query_client)
    else:
        server = AuthorizationServer(app, query_client=query_client)
    if use_cache:
        cache = SimpleCache()
        register_nonce_hooks(server, cache)
        register_temporary_credential_hooks(server, cache)
        server.register_hook("create_token_credential", create_token_credential)
    else:
        server.register_hook("exists_nonce", exists_nonce)
        server.register_hook("create_temporary_credential", create_temporary_credential)
        server.register_hook("get_temporary_credential", get_temporary_credential)
        server.register_hook("delete_temporary_credential", delete_temporary_credential)
        server.register_hook(
            "create_authorization_verifier", create_authorization_verifier
        )
        server.register_hook("create_token_credential", create_token_credential)

    @app.route("/oauth/initiate", methods=["GET", "POST"])
    def initiate():
        return server.create_temporary_credentials_response()

    @app.route("/oauth/authorize", methods=["GET", "POST"])
    def authorize():
        if request.method == "GET":
            try:
                server.check_authorization_request()
                return "ok"
            except OAuth1Error:
                return "error"
        user_id = request.form.get("user_id")
        if user_id:
            grant_user = db.session.get(User, int(user_id))
        else:
            grant_user = None
        try:
            return server.create_authorization_response(grant_user=grant_user)
        except OAuth1Error as error:
            return url_encode(error.get_body())

    @app.route("/oauth/token", methods=["POST"])
    def issue_token():
        return server.create_token_response()

    return server


def create_resource_server(app, use_cache=False, lazy=False):
    if use_cache:
        cache = SimpleCache()
        exists_nonce = create_cache_exists_nonce_func(cache)
    else:

        def exists_nonce(nonce, timestamp, client_id, oauth_token):
            q = db.session.query(TimestampNonce.nonce).filter_by(
                nonce=nonce,
                timestamp=timestamp,
                client_id=client_id,
            )
            if oauth_token:
                q = q.filter_by(oauth_token=oauth_token)
            rv = q.first()
            if rv:
                return True

            tn = TimestampNonce(
                nonce=nonce,
                timestamp=timestamp,
                client_id=client_id,
                oauth_token=oauth_token,
            )
            db.session.add(tn)
            db.session.commit()
            return False

    def query_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    def query_token(client_id, oauth_token):
        return TokenCredential.query.filter_by(
            client_id=client_id, oauth_token=oauth_token
        ).first()

    if lazy:
        require_oauth = ResourceProtector()
        require_oauth.init_app(app, query_client, query_token, exists_nonce)
    else:
        require_oauth = ResourceProtector(app, query_client, query_token, exists_nonce)

    @app.route("/user")
    @require_oauth()
    def user_profile():
        user = current_credential.user
        return jsonify(id=user.id, username=user.username)


def create_flask_app():
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
