"""An OAuth 2 provider that answers the requests of the client examples.

The client examples call real services, such as GitHub or Google. The tests
send these requests to this provider instead. The provider accepts every
client, secret and redirect URI, so that the examples work with their
placeholder values, and checks the secrets of the clients that the examples
use. It chooses the endpoint from the last part of the path, whatever the
host. Google issues its tokens on another host than its issuer.
"""

import time
from unittest import mock
from urllib.parse import urlsplit

import httpx2
import requests
from flask import Flask
from flask import jsonify
from flask import request as flask_request
from flask_sqlalchemy import SQLAlchemy
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.integrations.sqla_oauth2 import OAuth2AuthorizationCodeMixin
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2 import OAuth2TokenMixin
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from authlib.oauth2 import AuthorizationSession
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oidc.core import UserInfo
from authlib.oidc.core import grants as oidc_grants

USERNAME = "alice"

_AUTH_METHODS = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "none",
]

_CLIENTS = {
    "client-id": "client-secret",
    "client_id": "client_secret",
    "your-client-id": "your-client-secret",
    "{{ your-github-client-id }}": "{{ your-github-client-secret }}",
    "Your GitHub client ID": "Your GitHub client secret",
    "Your Google client ID": "Your Google client secret",
}

_ISSUERS = {"oauth2.googleapis.com": "https://accounts.google.com"}


class LoggedInSession(AuthorizationSession):
    """A session where the user has just logged in."""

    def get_interaction_time(self, request, interaction):
        if interaction == "login":
            return int(time.time())

        return None


class OAuthProvider:
    """A permissive OAuth 2 and OpenID Connect provider."""

    def __init__(self, key=None):
        self.key = key or RSAKey.generate_key(
            2048, parameters={"kid": "provider"}, private=True
        )
        self.app = Flask("provider")
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite://",
            OAUTH2_REFRESH_TOKEN_GENERATOR=True,
            PROPAGATE_EXCEPTIONS=True,
        )
        self.db = SQLAlchemy(self.app)
        self._define_models()
        self._define_server()
        self._define_routes()
        with self.app.app_context():
            self.db.create_all()

        self._patches = [
            mock.patch.object(HTTPAdapter, "send", _requests_send(self)),
            mock.patch.object(
                httpx2.HTTPTransport, "handle_request", _httpx_send(self)
            ),
            mock.patch.object(
                httpx2.AsyncHTTPTransport,
                "handle_async_request",
                _httpx_async_send(self),
            ),
        ]

    def start(self):
        """Send the HTTP requests of requests and httpx to the provider."""
        for patch in self._patches:
            patch.start()

    def stop(self):
        """Send the HTTP requests to the network again, and close the database."""
        for patch in self._patches:
            patch.stop()

        with self.app.app_context():
            self.db.engine.dispose()

    def handle(self, method, url, headers, body):
        """Answer a request with the status, the headers and the body."""
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        response = self.app.test_client().open(
            path,
            method=method,
            base_url=f"{parts.scheme}://{parts.netloc}",
            headers=dict(headers or {}),
            data=body or b"",
        )
        return response.status_code, dict(response.headers), response.get_data()

    def authorize(self, url):
        """Give the consent of the user, and return the redirect URI."""
        status, headers, body = self.handle("GET", url, {}, b"")
        assert status in (302, 303), body
        return headers["Location"]

    def _define_models(self):
        """Define the models of the provider."""
        db = self.db

        class User(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(40), unique=True)

            def get_user_id(self):
                return self.id

        class Client(db.Model, OAuth2ClientMixin):
            id = db.Column(db.Integer, primary_key=True)

            def check_redirect_uri(self, redirect_uri):
                return True

            def check_endpoint_auth_method(self, method, endpoint):
                return True

            def check_grant_type(self, grant_type):
                return True

            def check_response_type(self, response_type):
                return True

            def get_allowed_scope(self, scope):
                return scope or ""

            def get_default_redirect_uri(self):
                return "https://example.com/cb"

        class Token(db.Model, OAuth2TokenMixin):
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
            user = db.relationship("User")

        class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

        self.User = User
        self.Client = Client
        self.Token = Token
        self.AuthorizationCode = AuthorizationCode

    def get_user(self, username=USERNAME):
        """Return the user, and create it on first use."""
        user = self.User.query.filter_by(username=username).first()
        if user is None:
            user = self.User(username=username)
            self.db.session.add(user)
            self.db.session.commit()

        return user

    def _query_client(self, client_id):
        """Return a client of the examples."""
        client = self.Client.query.filter_by(client_id=client_id).first()
        if client is None and client_id in _CLIENTS:
            client = self.Client(client_id=client_id, client_secret=_CLIENTS[client_id])
            self.db.session.add(client)
            self.db.session.commit()

        return client

    def _save_token(self, token_data, request):
        """Save the issued token."""
        user_id = request.user.get_user_id() if request.user else None
        token = self.Token(
            client_id=request.client.client_id, user_id=user_id, **token_data
        )
        self.db.session.add(token)
        self.db.session.commit()

    def _define_server(self):
        """Define the authorization server, its grants and its endpoints."""
        provider = self
        db = self.db

        class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = _AUTH_METHODS

            def save_authorization_code(self, code, request):
                item = provider.AuthorizationCode(
                    code=code,
                    client_id=request.client.client_id,
                    redirect_uri=request.payload.redirect_uri,
                    scope=request.scope,
                    user_id=request.user.id,
                    nonce=request.payload.data.get("nonce"),
                    auth_time=request.auth_time,
                    code_challenge=request.payload.data.get("code_challenge"),
                    code_challenge_method=request.payload.data.get(
                        "code_challenge_method"
                    ),
                )
                db.session.add(item)
                db.session.commit()
                return item

            def query_authorization_code(self, code, client):
                return provider.AuthorizationCode.query.filter_by(
                    code=code, client_id=client.client_id
                ).first()

            def delete_authorization_code(self, authorization_code):
                db.session.delete(authorization_code)
                db.session.commit()

            def authenticate_user(self, authorization_code):
                return db.session.get(provider.User, authorization_code.user_id)

        class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = _AUTH_METHODS

            def authenticate_user(self, username, password):
                return provider.get_user(username)

        class RefreshTokenGrant(grants.RefreshTokenGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = _AUTH_METHODS
            INCLUDE_NEW_REFRESH_TOKEN = True

            def authenticate_refresh_token(self, refresh_token):
                item = provider.Token.query.filter_by(
                    refresh_token=refresh_token
                ).first()
                if item and not item.refresh_token_revoked_at:
                    return item

            def authenticate_user(self, credential):
                return db.session.get(provider.User, credential.user_id)

            def revoke_old_credential(self, credential):
                credential.refresh_token_revoked_at = int(time.time())
                db.session.commit()

        class OpenIDCode(oidc_grants.OpenIDCode):
            def resolve_client_private_key(self, client):
                return provider.key

            def get_client_claims(self, client):
                return {"iss": provider.issuer()}

            def exists_nonce(self, nonce, request):
                return False

            def generate_user_info(self, user, scope):
                return UserInfo(sub=str(user.id), name=user.username.title()).filter(
                    scope
                )

        class MyIntrospectionEndpoint(IntrospectionEndpoint):
            def query_token(self, token, token_type_hint):
                return provider.Token.query.filter_by(access_token=token).first()

            def introspect_token(self, token):
                return {
                    "active": True,
                    "client_id": token.client_id,
                    "scope": token.get_scope(),
                    "exp": token.issued_at + token.expires_in,
                }

            def check_permission(self, token, client, request):
                return True

        server = AuthorizationServer(
            self.app, query_client=self._query_client, save_token=self._save_token
        )
        server.register_grant(
            AuthorizationCodeGrant,
            [CodeChallenge(required=False), OpenIDCode(require_nonce=False)],
        )
        server.register_grant(grants.ImplicitGrant)
        server.register_grant(PasswordGrant)

        class ClientCredentialsGrant(grants.ClientCredentialsGrant):
            TOKEN_ENDPOINT_AUTH_METHODS = _AUTH_METHODS

        class ClientSecretJWTAuth(JWTBearerClientAssertion):
            CLIENT_AUTH_METHOD = "client_secret_jwt"

            def get_audiences(self):
                return [flask_request.base_url]

            def validate_jti(self, claims, jti):
                return True

            def resolve_client_public_key(self, client):
                return OctKey.import_key(client.client_secret)

        server.register_grant(ClientCredentialsGrant)
        server.register_client_auth_method(
            ClientSecretJWTAuth.CLIENT_AUTH_METHOD, ClientSecretJWTAuth()
        )
        server.register_grant(RefreshTokenGrant)
        server.register_endpoint(create_revocation_endpoint(db.session, self.Token))
        server.register_endpoint(MyIntrospectionEndpoint)
        self.server = server

        self.require_oauth = ResourceProtector()
        self.require_oauth.register_token_validator(
            create_bearer_token_validator(db.session, self.Token)()
        )

    def issuer(self):
        """Return the issuer, from the host of the request."""
        return _ISSUERS.get(flask_request.host, f"https://{flask_request.host}")

    def metadata(self):
        """Return the server metadata, with endpoints on the host of the request."""
        issuer = self.issuer()
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "revocation_endpoint": f"{issuer}/revoke",
            "introspection_endpoint": f"{issuer}/introspect",
            "jwks_uri": f"{issuer}/certs",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def _define_routes(self):
        """Answer every path with the endpoint of its last part."""
        provider = self
        server = self.server

        @self.app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
        def dispatch(path):
            name = path.rstrip("/").rsplit("/", 1)[-1]
            if path.endswith(("openid-configuration", "oauth-authorization-server")):
                return jsonify(provider.metadata())

            if name in ("authorize", "auth"):
                user = provider.get_user()
                session = LoggedInSession(user, {})
                grant = server.get_consent_grant(session=session)
                return server.create_authorization_response(
                    grant=grant, grant_user=user
                )

            if name in ("token", "access_token"):
                return server.create_token_response()

            if name == "revoke":
                return server.create_endpoint_response("revocation")

            if name == "introspect":
                return server.create_endpoint_response("introspection")

            if name in ("certs", "jwks", "jwks.json"):
                return jsonify(KeySet([provider.key]).as_dict(private=False))

            return provider.require_oauth()(provider.resource)()

    def resource(self):
        """Return the user of the token, for any protected resource."""
        user = current_token.user
        if user is None:
            return jsonify(client_id=current_token.client_id)

        return jsonify(sub=str(user.id), name=user.username.title())


def _requests_send(provider):
    """Return a replacement of HTTPAdapter.send."""

    def send(adapter, request, **kwargs):
        status, headers, body = provider.handle(
            request.method, request.url, request.headers, request.body
        )
        response = requests.Response()
        response.status_code = status
        response.headers = CaseInsensitiveDict(headers)
        response._content = body
        response.url = request.url
        response.request = request
        response.encoding = "utf-8"
        return response

    return send


def _httpx_send(provider):
    """Return a replacement of HTTPTransport.handle_request."""

    def handle_request(transport, request):
        status, headers, body = provider.handle(
            request.method, str(request.url), request.headers, request.read()
        )
        return httpx2.Response(status, headers=headers, content=body, request=request)

    return handle_request


def _httpx_async_send(provider):
    """Return a replacement of AsyncHTTPTransport.handle_async_request."""

    async def handle_async_request(transport, request):
        status, headers, body = provider.handle(
            request.method, str(request.url), request.headers, await request.aread()
        )
        return httpx2.Response(status, headers=headers, content=body, request=request)

    return handle_async_request
