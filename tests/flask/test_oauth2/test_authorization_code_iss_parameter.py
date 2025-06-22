from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc9207 import IssuerParameter as _IssuerParameter

from .models import Client
from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import TestCase
from .oauth2_server import create_authorization_server


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class IssuerParameter(_IssuerParameter):
    def get_issuer(self) -> str:
        return "https://auth.test"


class RFC9207AuthorizationCodeTest(TestCase):
    LAZY_INIT = False

    def prepare_data(
        self,
        is_confidential=True,
        response_type="code",
        grant_type="authorization_code",
        token_endpoint_auth_method="client_secret_basic",
        rfc9207=True,
    ):
        server = create_authorization_server(self.app, self.LAZY_INIT)
        if rfc9207:
            server.register_extension(IssuerParameter())
        server.register_grant(AuthorizationCodeGrant)
        self.server = server

        user = User(username="foo")
        db.session.add(user)
        db.session.commit()

        if is_confidential:
            client_secret = "code-secret"
        else:
            client_secret = ""
        client = Client(
            user_id=user.id,
            client_id="code-client",
            client_secret=client_secret,
        )
        client.set_client_metadata(
            {
                "redirect_uris": ["https://a.b"],
                "scope": "profile address",
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "response_types": [response_type],
                "grant_types": grant_type.splitlines(),
            }
        )
        self.authorize_url = "/oauth/authorize?response_type=code&client_id=code-client"
        db.session.add(client)
        db.session.commit()

    def test_rfc9207_enabled_success(self):
        """Check that when RFC9207 is implemented,
        the authorization response has an ``iss`` parameter."""

        self.prepare_data(rfc9207=True)
        url = self.authorize_url + "&state=bar"
        rv = self.client.post(url, data={"user_id": "1"})
        assert "iss=https%3A%2F%2Fauth.test" in rv.location

    def test_rfc9207_disabled_success_no_iss(self):
        """Check that when RFC9207 is not implemented,
        the authorization response contains no ``iss`` parameter."""

        self.prepare_data(rfc9207=False)
        url = self.authorize_url + "&state=bar"
        rv = self.client.post(url, data={"user_id": "1"})
        assert "iss=" not in rv.location

    def test_rfc9207_enabled_error(self):
        """Check that when RFC9207 is implemented,
        the authorization response has an ``iss`` parameter,
        even when an error is returned."""

        self.prepare_data(rfc9207=True)
        rv = self.client.post(self.authorize_url)
        assert "error=access_denied" in rv.location
        assert "iss=https%3A%2F%2Fauth.test" in rv.location

    def test_rfc9207_disbled_error_no_iss(self):
        """Check that when RFC9207 is not implemented,
        the authorization response contains no ``iss`` parameter,
        even when an error is returned."""

        self.prepare_data(rfc9207=False)
        rv = self.client.post(self.authorize_url)
        assert "error=access_denied" in rv.location
        assert "iss=" not in rv.location
