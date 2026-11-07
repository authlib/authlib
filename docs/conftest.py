"""Run the Python examples of the documentation with Sybil.

Each page gets the objects that the previous pages of its guide define, and
the names that the modules of the guide export. The examples may show their
imports or not.
"""

import doctest
import functools
import importlib
import json
import os
import pkgutil
import re
import tempfile
import time

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from joserfc.jwk import KeySet
from joserfc.jwk import RSAKey
from sybil import Region
from sybil import Sybil
from sybil.parsers.rest import DocTestParser
from sybil.parsers.rest import PythonCodeBlockParser
from sybil.parsers.rest import SkipParser

import authlib.oauth2
import authlib.oidc
from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.oauth2 import AuthorizationSession
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint

_FLASK_SERVER = "oauth2/authorization-server/flask/"
_FLASK_SERVER_MODULES = [
    "flask",
    "authlib.oauth2",
    "authlib.oauth2.rfc6749",
    "authlib.oauth2.rfc7636",
    "authlib.oidc.core",
    "authlib.integrations.sqla_oauth2",
    "authlib.integrations.flask_oauth2",
]


@functools.cache
def _rsa_key(kid):
    """Generate an RSA key once for all pages."""
    return RSAKey.generate_key(2048, parameters={"kid": kid}, private=True)


class _LoggedInSession(AuthorizationSession):
    """A session where the user has just logged in."""

    def get_interaction_time(self, request, interaction):
        if interaction == "login":
            return int(time.time())

        return None


_MODULE_DIRECTIVE = re.compile(r"^\.\. (?:current)?module:: (\S+)", re.MULTILINE)


def _import_module(namespace, module_name):
    """Add the names that a module exports."""
    module = importlib.import_module(module_name)
    names = getattr(module, "__all__", None)
    if names is None:
        names = [name for name in vars(module) if not name.startswith("_")]

    namespace.update({name: getattr(module, name) for name in names})


def _import_names(namespace, modules):
    """Add the exported names of the modules, the last module wins.

    The specifications are also available by their module name, such as
    rfc9101, and the OpenID Connect package as oidc.
    """
    namespace.update(json=json, time=time, grants=grants, oidc=authlib.oidc)
    for module in pkgutil.iter_modules(authlib.oauth2.__path__):
        namespace[module.name] = importlib.import_module(
            f"authlib.oauth2.{module.name}"
        )

    for module_name in modules:
        _import_module(namespace, module_name)


def _evaluate_module_directive(example):
    """Add the names of the module that the directive declares."""
    _import_module(example.namespace, example.parsed)


def _parse_module_directives(document):
    """Give the next examples the names of each module directive."""
    for match in _MODULE_DIRECTIVE.finditer(document.text):
        yield Region(
            match.start(), match.end(), match.group(1), _evaluate_module_directive
        )


def _setup_flask_app(namespace):
    """Create the Flask application and the database of the guide."""
    _import_names(namespace, _FLASK_SERVER_MODULES)
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["OAUTH2_REFRESH_TOKEN_GENERATOR"] = True
    app.config["PROPAGATE_EXCEPTIONS"] = True
    db = SQLAlchemy(app)
    context = app.app_context()
    context.push()
    namespace.update(app=app, db=db, _context=context)


def _setup_flask_server(namespace):
    """Define what the authorization server page defines."""
    _setup_flask_app(namespace)
    app = namespace["app"]
    db = namespace["db"]

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(40), unique=True)
        password = db.Column(db.String(40))
        name = db.Column(db.String(40))
        email = db.Column(db.String(40))

        def get_user_id(self):
            return self.id

        def check_password(self, password):
            return password == self.password

    class Client(db.Model, OAuth2ClientMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    class Token(db.Model, OAuth2TokenMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
        user = db.relationship("User")

    def query_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    def save_token(token_data, request):
        user_id = request.user.get_user_id() if request.user else None
        token = Token(client_id=request.client.client_id, user_id=user_id, **token_data)
        db.session.add(token)
        db.session.commit()

    server = AuthorizationServer(app, query_client=query_client, save_token=save_token)

    def _authorize():
        """Authorize the request for the first user."""
        user = User.query.first()
        session = _LoggedInSession(user, {})
        grant = server.get_consent_grant(session=session)
        return server.create_authorization_response(grant=grant, grant_user=user)

    def _issue_token():
        """Issue a token."""
        return server.create_token_response()

    app.add_url_rule("/test/authorize", view_func=_authorize, methods=["POST"])
    app.add_url_rule("/test/token", view_func=_issue_token, methods=["POST"])

    def create_client(client_id="client-id", **metadata):
        """Create the tables and a client for the hidden flows."""
        db.create_all()
        client = Client(client_id=client_id, client_secret="client-secret")
        client.set_client_metadata({"scope": "profile", **metadata})
        db.session.add(client)
        db.session.commit()
        return client

    def create_token(client, **values):
        """Create a token of the client for the hidden flows."""
        token = Token(
            client_id=client.client_id,
            token_type="Bearer",
            access_token=generate_token(),
            refresh_token=generate_token(),
            scope="profile",
            expires_in=3600,
            **values,
        )
        db.session.add(token)
        db.session.commit()
        return token

    namespace.update(
        User=User,
        Client=Client,
        Token=Token,
        server=server,
        create_client=create_client,
        create_token=create_token,
    )


def _setup_flask_oidc(namespace):
    """Define what the authorization server and grants pages define."""
    _setup_flask_server(namespace)
    db = namespace["db"]
    user_model = namespace["User"]

    class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
        def query_authorization_code(self, code, client):
            return AuthorizationCode.query.filter_by(
                code=code, client_id=client.client_id
            ).first()

        def delete_authorization_code(self, authorization_code):
            db.session.delete(authorization_code)
            db.session.commit()

        def authenticate_user(self, authorization_code):
            return db.session.get(user_model, authorization_code.user_id)

    jwks = KeySet([_rsa_key("example")])
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(jwks.as_dict(private=True), f)

    namespace.update(
        AuthorizationCode=AuthorizationCode,
        _AuthorizationCodeGrant=AuthorizationCodeGrant,
        jwks_file_path=path,
        public_jwks=KeySet.import_key_set(jwks.as_dict(private=False)),
    )


def _teardown_flask(namespace):
    """Close the application context and remove the files of the setup."""
    if "_context" in namespace:
        engine = namespace["db"].engine
        namespace["_context"].pop()
        engine.dispose()

    if "jwks_file_path" in namespace:
        os.remove(namespace["jwks_file_path"])


def _setup_flask_specs(namespace):
    """Define what the Flask guide defines, for the specification pages."""
    _setup_flask_oidc(namespace)

    class MyClientRegistrationEndpoint(ClientRegistrationEndpoint):
        pass

    class MyBearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return namespace["Token"].query.filter_by(access_token=token_string).first()

    namespace.update(
        authorization_server=namespace["server"],
        require_oauth=ResourceProtector(),
        client_secret="client-secret",
        private_key=_rsa_key("private"),
        provider_metadata={
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
        MyClientRegistrationEndpoint=MyClientRegistrationEndpoint,
        MyBearerTokenValidator=MyBearerTokenValidator,
    )


def _sybil(pattern, setup):
    """Run the examples of the pages that match the pattern."""
    return Sybil(
        parsers=[
            _parse_module_directives,
            PythonCodeBlockParser(),
            DocTestParser(optionflags=doctest.ELLIPSIS),
            SkipParser(),
        ],
        patterns=[pattern],
        setup=setup,
        teardown=_teardown_flask,
    )


_sybils = _sybil(_FLASK_SERVER + "authorization-server.rst", _setup_flask_app) + _sybil(
    _FLASK_SERVER + "grants.rst", _setup_flask_server
)
_sybils.append(_sybil(_FLASK_SERVER + "openid-connect.rst", _setup_flask_oidc))
_sybils.append(_sybil("oauth2/specs/*.rst", _setup_flask_specs))
pytest_collect_file = _sybils.pytest()
