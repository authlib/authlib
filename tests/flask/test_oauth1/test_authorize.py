from tests.util import decode_response

from .oauth1_server import Client
from .oauth1_server import TestCase
from .oauth1_server import User
from .oauth1_server import create_authorization_server
from .oauth1_server import db


class AuthorizationWithCacheTest(TestCase):
    USE_CACHE = True

    def prepare_data(self):
        create_authorization_server(self.app, self.USE_CACHE, self.USE_CACHE)
        user = User(username="foo")
        db.session.add(user)
        db.session.commit()
        client = Client(
            user_id=user.id,
            client_id="client",
            client_secret="secret",
            default_redirect_uri="https://a.b",
        )
        db.session.add(client)
        db.session.commit()

    def test_invalid_authorization(self):
        self.prepare_data()
        url = "/oauth/authorize"

        # case 1
        rv = self.client.post(url, data={"user_id": "1"})
        data = decode_response(rv.data)
        assert data["error"] == "missing_required_parameter"
        assert "oauth_token" in data["error_description"]

        # case 2
        rv = self.client.post(url, data={"user_id": "1", "oauth_token": "a"})
        data = decode_response(rv.data)
        assert data["error"] == "invalid_token"

    def test_authorize_denied(self):
        self.prepare_data()
        initiate_url = "/oauth/initiate"
        authorize_url = "/oauth/authorize"

        rv = self.client.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "oob",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        data = decode_response(rv.data)
        assert "oauth_token" in data

        rv = self.client.post(authorize_url, data={"oauth_token": data["oauth_token"]})
        assert rv.status_code == 302
        assert "access_denied" in rv.headers["Location"]
        assert "https://a.b" in rv.headers["Location"]

        rv = self.client.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "https://i.test",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        data = decode_response(rv.data)
        assert "oauth_token" in data

        rv = self.client.post(authorize_url, data={"oauth_token": data["oauth_token"]})
        assert rv.status_code == 302
        assert "access_denied" in rv.headers["Location"]
        assert "https://i.test" in rv.headers["Location"]

    def test_authorize_granted(self):
        self.prepare_data()
        initiate_url = "/oauth/initiate"
        authorize_url = "/oauth/authorize"

        rv = self.client.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "oob",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        data = decode_response(rv.data)
        assert "oauth_token" in data

        rv = self.client.post(
            authorize_url, data={"user_id": "1", "oauth_token": data["oauth_token"]}
        )
        assert rv.status_code == 302
        assert "oauth_verifier" in rv.headers["Location"]
        assert "https://a.b" in rv.headers["Location"]

        rv = self.client.post(
            initiate_url,
            data={
                "oauth_consumer_key": "client",
                "oauth_callback": "https://i.test",
                "oauth_signature_method": "PLAINTEXT",
                "oauth_signature": "secret&",
            },
        )
        data = decode_response(rv.data)
        assert "oauth_token" in data

        rv = self.client.post(
            authorize_url, data={"user_id": "1", "oauth_token": data["oauth_token"]}
        )
        assert rv.status_code == 302
        assert "oauth_verifier" in rv.headers["Location"]
        assert "https://i.test" in rv.headers["Location"]


class AuthorizationNoCacheTest(AuthorizationWithCacheTest):
    USE_CACHE = False
