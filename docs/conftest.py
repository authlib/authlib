"""Run the Python examples of the documentation with Sybil.

Each page gets the objects that the previous pages of its guide define, and
the names that the modules of the guide export. The examples may show their
imports or not.
"""

import ast
import asyncio
import doctest
import functools
import importlib
import inspect
import json
import os
import pkgutil
import re
import tempfile
import time
import unittest
from pathlib import Path

import httpx2
import requests
from _oauth_provider import LoggedInSession
from _oauth_provider import OAuth1Provider
from _oauth_provider import OAuthProvider
from cachelib import SimpleCache
from django.apps import apps
from django.conf import settings
from django.db import connection
from django.test import RequestFactory
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from joserfc.jwk import KeySet
from joserfc.jwk import RSAKey
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from sybil import Document
from sybil import Region
from sybil import Sybil
from sybil.evaluators.python import PythonEvaluator
from sybil.evaluators.python import pad
from sybil.parsers.rest import CodeBlockParser
from sybil.parsers.rest import DocTestParser
from sybil.parsers.rest import SkipParser

import authlib.oauth2
import authlib.oidc
from authlib.common.security import generate_token
from authlib.integrations.django_client import token_update as django_token_update
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.oauth1.rfc5849.base_server import BaseServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint

_DOCS = Path(__file__).parent
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


_MODULE_DIRECTIVE = re.compile(r"^\.\. (?:current)?module:: (\S+)", re.MULTILINE)


def _import_module(namespace, module_name):
    """Add the names that a module exports."""
    module = importlib.import_module(module_name)
    names = getattr(module, "__all__", None)
    if names is None:
        names = [
            name
            for name, value in vars(module).items()
            if not name.startswith("_") and not inspect.ismodule(value)
        ]

    namespace.update({name: getattr(module, name) for name in names})


def _import_names(namespace, modules):
    """Add the exported names of the modules, the last module wins."""
    namespace.update(json=json, time=time, rsa_key=_rsa_key)
    for module_name in modules:
        _import_module(namespace, module_name)


def _import_oauth2_names(namespace, modules):
    """Add the names of an OAuth 2 guide.

    The specifications are also available by their module name, such as
    rfc9101, and the OpenID Connect package as oidc.
    """
    namespace.update(grants=grants, oidc=authlib.oidc)
    for module in pkgutil.iter_modules(authlib.oauth2.__path__):
        namespace[module.name] = importlib.import_module(
            f"authlib.oauth2.{module.name}"
        )

    _import_names(namespace, modules)


def _evaluate_module_directive(example):
    """Add the names of the module that the directive declares."""
    _import_module(example.namespace, example.parsed)


def _parse_module_directives(document):
    """Give the next examples the names of each module directive."""
    for match in _MODULE_DIRECTIVE.finditer(document.text):
        yield Region(
            match.start(), match.end(), match.group(1), _evaluate_module_directive
        )


class _AwaitPythonEvaluator(PythonEvaluator):
    """Run a Python example that may use await outside of a function.

    The examples of a page share one event loop, as they share their objects.
    """

    def __init__(self):
        super().__init__()
        self.flags |= ast.PyCF_ALLOW_TOP_LEVEL_AWAIT

    def __call__(self, example):
        source = pad(example.parsed, example.line + example.parsed.line_offset)
        code = compile(
            source, example.path, "exec", flags=self.flags, dont_inherit=True
        )
        result = eval(code, example.namespace)
        del example.namespace["__builtins__"]
        if not inspect.iscoroutine(result):
            return

        if "_loop" not in example.namespace:
            example.namespace["_loop"] = asyncio.new_event_loop()

        example.namespace["_loop"].run_until_complete(result)


_PARSERS = [
    _parse_module_directives,
    CodeBlockParser(language="python", evaluator=_AwaitPythonEvaluator()),
    DocTestParser(optionflags=doctest.ELLIPSIS),
    SkipParser(),
]


class _DocsFlask(Flask):
    """A Flask application where a view replaces the previous view of the same name.

    The pages show several versions of the same view.
    """

    def add_url_rule(self, rule, endpoint=None, view_func=None, **options):
        endpoint = endpoint or (view_func and view_func.__name__)
        previous = self.view_functions.get(endpoint)
        if previous is not None and previous is not view_func:
            del self.view_functions[endpoint]
            old = self.url_map
            rules = [r.empty() for r in old.iter_rules() if r.endpoint != endpoint]
            self.url_map = self.url_map_class(
                rules,
                default_subdomain=old.default_subdomain,
                strict_slashes=old.strict_slashes,
                merge_slashes=old.merge_slashes,
                redirect_defaults=old.redirect_defaults,
                converters=old.converters,
                sort_parameters=old.sort_parameters,
                sort_key=old.sort_key,
                host_matching=old.host_matching,
            )

        super().add_url_rule(rule, endpoint, view_func, **options)


def _run_page(namespace, page):
    """Run the examples of a page in the namespace, as the setup of another page."""
    document = Document.parse(str(_DOCS / page), *_PARSERS)
    document.namespace = namespace
    for example in document.examples():
        try:
            example.evaluate()
        except unittest.SkipTest:
            continue


def _setup_flask_app(namespace):
    """Give the names of the OAuth 2 Flask guide, and create its application."""
    _import_oauth2_names(namespace, _FLASK_SERVER_MODULES)
    _create_flask_app(namespace)


def _create_flask_app(namespace):
    """Create the Flask application and the database."""
    app = _DocsFlask(__name__)
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
        session = LoggedInSession(user, {})
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

    namespace.update(
        AuthorizationCode=AuthorizationCode,
        _AuthorizationCodeGrant=AuthorizationCodeGrant,
    )
    _write_jwks(namespace)


def _write_jwks(namespace):
    """Write the private keys of the server to a file, as the pages read them."""
    jwks = KeySet([_rsa_key("example")])
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(jwks.as_dict(private=True), f)

    namespace.update(
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


_DJANGO_APP = "docs"
_DJANGO_MODULES = [
    "django.db.models",
    "django.http",
    "django.views.decorators.http",
    "authlib.oauth2",
    "authlib.oauth2.rfc6749",
    "authlib.oauth2.rfc7636",
    "authlib.oidc.core",
    "authlib.integrations.django_oauth2",
]


def _create_django_tables():
    """Create the tables of the models that the page defines."""
    with connection.schema_editor() as editor:
        for model in apps.get_app_config(_DJANGO_APP).get_models():
            editor.create_model(model)


def _setup_django(namespace):
    """Give the names of the OAuth 2 Django guide, and its settings and keys."""
    _import_oauth2_names(namespace, _DJANGO_MODULES)
    namespace["_provider_settings"] = getattr(settings, "AUTHLIB_OAUTH2_PROVIDER", None)
    settings.AUTHLIB_OAUTH2_PROVIDER = {"refresh_token_generator": True}
    _write_jwks(namespace)
    _create_django_app(namespace)


def _create_django_app(namespace):
    """Attach the models of the page to an app, and allow HTTP requests."""
    from django.contrib.auth.models import User

    namespace.update(
        __name__=f"tests.django.{_DJANGO_APP}.models",
        User=User,
        request_factory=RequestFactory(),
        create_tables=_create_django_tables,
        _insecure_transport=os.environ.get("AUTHLIB_INSECURE_TRANSPORT"),
    )
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"


def _setup_django_server(namespace):
    """Define what the Django authorization server page defines."""
    _setup_django(namespace)
    _run_page(namespace, "oauth2/authorization-server/django/authorization-server.rst")
    namespace["_AuthorizationCodeGrant"] = grants.AuthorizationCodeGrant


def _restore_insecure_transport(namespace):
    """Restore the AUTHLIB_INSECURE_TRANSPORT variable of before the setup."""
    if namespace["_insecure_transport"] is None:
        os.environ.pop("AUTHLIB_INSECURE_TRANSPORT", None)
    else:
        os.environ["AUTHLIB_INSECURE_TRANSPORT"] = namespace["_insecure_transport"]


def _teardown_django(namespace):
    """Drop the tables, forget the models and restore the settings."""
    if "_provider_settings" in namespace:
        if namespace["_provider_settings"] is None:
            del settings.AUTHLIB_OAUTH2_PROVIDER
        else:
            settings.AUTHLIB_OAUTH2_PROVIDER = namespace["_provider_settings"]

    if "jwks_file_path" in namespace:
        os.remove(namespace["jwks_file_path"])

    if "_signature_methods" in namespace:
        BaseServer.SIGNATURE_METHODS.clear()
        BaseServer.SIGNATURE_METHODS.update(namespace["_signature_methods"])

    _restore_insecure_transport(namespace)

    models = list(apps.get_app_config(_DJANGO_APP).get_models())
    blocker = namespace.get("django_db_blocker")
    if models and blocker:
        with blocker.unblock():
            tables = connection.introspection.table_names()
            with connection.schema_editor() as editor:
                for model in models:
                    if model._meta.db_table in tables:
                        editor.delete_model(model)

    apps.all_models[_DJANGO_APP].clear()
    apps.clear_cache()


def _teardown_nothing(namespace):
    """Leave the page as it is, for the pages that only import names."""


def _close_loop(teardown):
    """Close the event loop of the page after its teardown."""

    def close(namespace):
        try:
            teardown(namespace)
        finally:
            if "_loop" in namespace:
                namespace["_loop"].close()

    return close


def _sybil(pattern, setup, teardown=_teardown_flask, fixtures=(), excludes=()):
    """Run the examples of the pages that match the pattern."""
    return Sybil(
        parsers=_PARSERS,
        patterns=[pattern],
        excludes=list(excludes),
        setup=setup,
        teardown=_close_loop(teardown),
        fixtures=list(fixtures),
    )


_sybils = _sybil(_FLASK_SERVER + "authorization-server.rst", _setup_flask_app) + _sybil(
    _FLASK_SERVER + "grants.rst", _setup_flask_server
)
_sybils.append(_sybil(_FLASK_SERVER + "openid-connect.rst", _setup_flask_oidc))
_sybils.append(
    _sybil(
        "oauth2/specs/*.rst", _setup_flask_specs, excludes=["oauth2/specs/rfc7523.rst"]
    )
)


def _setup_flask_specs_with_provider(namespace):
    """Define what the Flask guide defines, and send the client requests to a provider."""
    provider = OAuthProvider(_rsa_key("provider"))
    provider.start()
    namespace["provider"] = provider
    _setup_flask_specs(namespace)


def _teardown_flask_specs_with_provider(namespace):
    """Stop the provider, and close the Flask application."""
    if "provider" in namespace:
        namespace["provider"].stop()

    _teardown_flask(namespace)


_sybils.append(
    _sybil(
        "oauth2/specs/rfc7523.rst",
        _setup_flask_specs_with_provider,
        _teardown_flask_specs_with_provider,
    )
)
for _page in [
    "oauth2/concepts.rst",
    "oauth2/authorization-server/index.rst",
    "oauth2/authorization-server/authorization-session.rst",
    _FLASK_SERVER + "index.rst",
    _FLASK_SERVER + "api.rst",
    _FLASK_SERVER + "endpoints.rst",
    "oauth2/resource-server/flask.rst",
]:
    _sybils.append(_sybil(_page, _setup_flask_specs))

_OAUTH1_FLASK_MODULES = [
    "flask",
    "authlib.oauth1",
    "authlib.oauth1.rfc5849",
    "authlib.integrations.flask_oauth1",
]
_OAUTH1_DJANGO_MODULES = [
    "django.db.models",
    "django.http",
    "django.views.decorators.http",
    "authlib.oauth1",
    "authlib.oauth1.rfc5849",
    "authlib.integrations.django_oauth1",
]


def _setup_oauth1_flask(namespace):
    """Give the names of the OAuth 1 Flask guide, and create its application."""
    _import_names(namespace, _OAUTH1_FLASK_MODULES)
    _create_flask_app(namespace)
    namespace.update(
        cache=SimpleCache(), _signature_methods=dict(BaseServer.SIGNATURE_METHODS)
    )


def _teardown_oauth1_flask(namespace):
    """Restore the signature methods that the pages register."""
    _teardown_flask(namespace)
    BaseServer.SIGNATURE_METHODS.clear()
    BaseServer.SIGNATURE_METHODS.update(namespace["_signature_methods"])


def _setup_oauth1_django(namespace):
    """Give the names of the OAuth 1 Django guide, and attach its models."""
    _import_names(namespace, _OAUTH1_DJANGO_MODULES)
    namespace["_signature_methods"] = dict(BaseServer.SIGNATURE_METHODS)
    _create_django_app(namespace)


def _setup_oauth1_flask_server(namespace):
    """Define what the OAuth 1 Flask authorization server page defines."""
    _setup_oauth1_flask(namespace)
    _run_page(namespace, "oauth1/provider/flask/authorization-server.rst")


def _setup_oauth1_django_server(namespace):
    """Define what the OAuth 1 Django authorization server page defines."""
    _setup_oauth1_django(namespace)
    _run_page(namespace, "oauth1/provider/django/authorization-server.rst")


for _page, _setup in [
    ("oauth1/concepts.rst", _setup_oauth1_flask),
    ("oauth1/specs/rfc5849.rst", _setup_oauth1_flask),
    ("oauth1/provider/flask/index.rst", _setup_oauth1_flask),
    ("oauth1/provider/flask/api.rst", _setup_oauth1_flask),
    ("oauth1/provider/flask/authorization-server.rst", _setup_oauth1_flask),
    ("oauth1/provider/flask/resource-server.rst", _setup_oauth1_flask_server),
    ("oauth1/provider/flask/customize.rst", _setup_oauth1_flask_server),
]:
    _sybils.append(_sybil(_page, _setup, _teardown_oauth1_flask))

for _page, _setup in [
    ("oauth1/provider/django/index.rst", _setup_oauth1_django),
    ("oauth1/provider/django/api.rst", _setup_oauth1_django),
    ("oauth1/provider/django/authorization-server.rst", _setup_oauth1_django),
    ("oauth1/provider/django/resource-server.rst", _setup_oauth1_django_server),
]:
    _sybils.append(
        _sybil(
            _page,
            _setup,
            _teardown_django,
            ["transactional_db", "django_db_blocker"],
        )
    )

_OAUTH2_CLIENT_MODULES = [
    "authlib.oauth2",
    "authlib.oauth2.rfc6749",
    "authlib.oauth2.rfc7523",
    "authlib.oauth2.rfc7636",
    "authlib.integrations.httpx_client",
    "authlib.integrations.requests_client",
]


def _setup_oauth2_client(namespace):
    """Send the requests of the client examples to a provider."""
    _start_oauth2_provider(namespace)
    _import_oauth2_names(namespace, _OAUTH2_CLIENT_MODULES)
    namespace.update(
        requests=requests,
        httpx2=httpx2,
        app=_DocsFlask(__name__),
        token=OAuth2Session("client-id", "client-secret").fetch_token(
            namespace["token_endpoint"], grant_type="client_credentials"
        ),
    )


def _teardown_client(namespace):
    """Send the requests to the network again."""
    if "provider" in namespace:
        namespace["provider"].stop()


for _page in [
    "oauth2/client/index.rst",
    "oauth2/client/http/*.rst",
]:
    _sybils.append(_sybil(_page, _setup_oauth2_client, _teardown_client))


def _start_provider(namespace, provider):
    """Send the HTTP requests of the page to a provider."""
    provider.start()
    namespace.update(provider=provider, consent=provider.authorize)


def _start_oauth2_provider(namespace):
    """Send the HTTP requests of the page to an OAuth 2 provider, and give the client values."""
    _start_provider(namespace, OAuthProvider(_rsa_key("provider")))
    namespace.update(
        client_id="client-id",
        client_secret="client-secret",
        token_endpoint="https://example.com/oauth/token",
        url="https://api.example.com/data",
        private_key=_rsa_key("private"),
    )


def _setup_flask_client(namespace):
    """Give the names of the Flask client guide, and its application."""
    _start_oauth2_provider(namespace)
    _import_oauth2_names(namespace, ["flask", "authlib.integrations.flask_client"])
    app = _DocsFlask(__name__)
    app.secret_key = "secret-key"
    namespace["app"] = app


def _setup_django_client(namespace):
    """Give the names of the Django client guide."""
    _start_oauth2_provider(namespace)
    _import_oauth2_names(
        namespace,
        ["django.http", "django.shortcuts", "authlib.integrations.django_client"],
    )


def _teardown_django_client(namespace):
    """Stop the provider, and disconnect the signal receivers of the page."""
    _teardown_client(namespace)
    if "on_token_update" in namespace:
        django_token_update.disconnect(namespace["on_token_update"])


def _setup_client_names(namespace):
    """Give the names of the OAuth 2 client guides, for the pages without requests."""
    _import_oauth2_names(namespace, _OAUTH2_CLIENT_MODULES)


def _setup_oauth1_client_names(namespace):
    """Give the names of the OAuth 1 client guides, for the pages without requests."""
    _import_names(namespace, _OAUTH1_CLIENT_MODULES)


def _setup_oauth1_index(namespace):
    """Give the names of the OAuth 1 client overview, and a Flask application."""
    _import_names(
        namespace, _OAUTH1_CLIENT_MODULES + ["authlib.integrations.flask_client"]
    )
    namespace["app"] = _DocsFlask(__name__)


def _setup_starlette_client(namespace):
    """Give the names of the Starlette client guide, and its application."""
    _start_oauth2_provider(namespace)
    _import_oauth2_names(
        namespace,
        ["starlette.responses", "authlib.integrations.starlette_client"],
    )
    middleware = [Middleware(SessionMiddleware, secret_key="secret-key")]
    namespace["app"] = Starlette(middleware=middleware)


_WEB_CLIENT = "oauth2/client/web/"
for _page, _setup in [
    (_WEB_CLIENT + "flask.rst", _setup_flask_client),
    (_WEB_CLIENT + "starlette.rst", _setup_starlette_client),
]:
    _sybils.append(_sybil(_page, _setup, _teardown_client))

for _page in [_WEB_CLIENT + "api.rst", _WEB_CLIENT + "fastapi.rst"]:
    _sybils.append(_sybil(_page, _setup_client_names, _teardown_nothing))

for _page in [_WEB_CLIENT + "index.rst", _WEB_CLIENT + "django.rst"]:
    _sybils.append(
        _sybil(
            _page,
            _setup_django_client,
            _teardown_django_client,
            ["django_test_environment"],
        )
    )

_OAUTH1_CLIENT_MODULES = [
    "authlib.oauth1",
    "authlib.integrations.httpx_client",
    "authlib.integrations.requests_client",
]


def _setup_oauth1_client(namespace):
    """Send the requests of the OAuth 1 client examples to a provider."""
    _start_provider(namespace, OAuth1Provider())
    _import_names(namespace, _OAUTH1_CLIENT_MODULES)
    namespace.update(requests=requests, httpx2=httpx2, app=_DocsFlask(__name__))


def _setup_oauth1_flask_client(namespace):
    """Give the names of the OAuth 1 Flask client guide, and its application."""
    _start_provider(namespace, OAuth1Provider())
    _import_names(namespace, ["flask", "authlib.integrations.flask_client"])
    app = _DocsFlask(__name__)
    app.secret_key = "secret-key"
    namespace.update(app=app, cache=SimpleCache())


def _setup_oauth1_django_client(namespace):
    """Give the names of the OAuth 1 Django client guide."""
    _start_provider(namespace, OAuth1Provider())
    _import_names(
        namespace,
        ["django.http", "django.shortcuts", "authlib.integrations.django_client"],
    )


def _setup_oauth1_starlette_client(namespace):
    """Give the names of the OAuth 1 Starlette client guide, and its application."""
    _start_provider(namespace, OAuth1Provider())
    _import_names(
        namespace,
        ["starlette.responses", "authlib.integrations.starlette_client"],
    )
    middleware = [Middleware(SessionMiddleware, secret_key="secret-key")]
    namespace["app"] = Starlette(middleware=middleware)


_OAUTH1_CLIENT = "oauth1/client/"
for _page, _setup in [
    (_OAUTH1_CLIENT + "http/*.rst", _setup_oauth1_client),
    (_OAUTH1_CLIENT + "web/flask.rst", _setup_oauth1_flask_client),
    (_OAUTH1_CLIENT + "web/starlette.rst", _setup_oauth1_starlette_client),
]:
    _sybils.append(_sybil(_page, _setup, _teardown_client))

for _page, _setup in [
    (_OAUTH1_CLIENT + "index.rst", _setup_oauth1_index),
    (_OAUTH1_CLIENT + "web/api.rst", _setup_oauth1_client_names),
    (_OAUTH1_CLIENT + "web/fastapi.rst", _setup_oauth1_client_names),
]:
    _sybils.append(_sybil(_page, _setup, _teardown_nothing))

for _page in [_OAUTH1_CLIENT + "web/index.rst", _OAUTH1_CLIENT + "web/django.rst"]:
    _sybils.append(
        _sybil(
            _page,
            _setup_oauth1_django_client,
            _teardown_django_client,
            ["django_test_environment"],
        )
    )

for _page, _setup in [
    ("basic/*.rst", _setup_flask_specs),
    ("community/*.rst", _setup_flask_specs),
    ("upgrades/jose.rst", _setup_flask_specs),
]:
    _sybils.append(_sybil(_page, _setup))

_DJANGO_SERVER = "oauth2/authorization-server/django/"
for _page, _setup in [
    (_DJANGO_SERVER + "index.rst", _setup_django),
    (_DJANGO_SERVER + "authorization-server.rst", _setup_django),
    (_DJANGO_SERVER + "api.rst", _setup_django),
    (_DJANGO_SERVER + "grants.rst", _setup_django_server),
    (_DJANGO_SERVER + "endpoints.rst", _setup_django_server),
    (_DJANGO_SERVER + "openid-connect.rst", _setup_django_server),
    ("oauth2/resource-server/django.rst", _setup_django_server),
]:
    _sybils.append(
        _sybil(
            _page,
            _setup,
            _teardown_django,
            ["transactional_db", "django_db_blocker"],
        )
    )

pytest_collect_file = _sybils.pytest()
