from unittest import TestCase
from unittest import mock

import pytest
from cachelib import SimpleCache
from flask import Flask
from flask import session

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.flask_client import FlaskOAuth2App
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client import OAuthError
from authlib.jose.rfc7517 import JsonWebKey
from authlib.oidc.core.grants.util import generate_id_token

from ..util import get_bearer_token
from ..util import mock_send_value


class FlaskOAuthTest(TestCase):
    def test_register_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        with pytest.raises(AttributeError):
            oauth.dev  # noqa:B018

        oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
        )
        assert oauth.dev.name == "dev"
        assert oauth.dev.client_id == "dev"

    def test_register_conf_from_app(self):
        app = Flask(__name__)
        app.config.update(
            {
                "DEV_CLIENT_ID": "dev",
                "DEV_CLIENT_SECRET": "dev",
            }
        )
        oauth = OAuth(app)
        oauth.register("dev")
        assert oauth.dev.client_id == "dev"

    def test_register_with_overwrite(self):
        app = Flask(__name__)
        app.config.update(
            {
                "DEV_CLIENT_ID": "dev-1",
                "DEV_CLIENT_SECRET": "dev",
                "DEV_ACCESS_TOKEN_PARAMS": {"foo": "foo-1"},
            }
        )
        oauth = OAuth(app)
        oauth.register(
            "dev", overwrite=True, client_id="dev", access_token_params={"foo": "foo"}
        )
        assert oauth.dev.client_id == "dev-1"
        assert oauth.dev.client_secret == "dev"
        assert oauth.dev.access_token_params["foo"] == "foo-1"

    def test_init_app_later(self):
        app = Flask(__name__)
        app.config.update(
            {
                "DEV_CLIENT_ID": "dev",
                "DEV_CLIENT_SECRET": "dev",
            }
        )
        oauth = OAuth()
        remote = oauth.register("dev")
        with pytest.raises(RuntimeError):
            oauth.dev.client_id  # noqa:B018
        oauth.init_app(app)
        assert oauth.dev.client_id == "dev"
        assert remote.client_id == "dev"

        assert oauth.cache is None
        assert oauth.fetch_token is None
        assert oauth.update_token is None

    def test_init_app_params(self):
        app = Flask(__name__)
        oauth = OAuth()
        oauth.init_app(app, SimpleCache())
        assert oauth.cache is not None
        assert oauth.update_token is None

        oauth.init_app(app, update_token=lambda o: o)
        assert oauth.update_token is not None

    def test_create_client(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        assert oauth.create_client("dev") is None
        oauth.register("dev", client_id="dev")
        assert oauth.create_client("dev") is not None

    def test_register_oauth1_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        client_kwargs = dict(
            client_id="dev",
            client_secret="dev",
            request_token_url="https://i.b/reqeust-token",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            fetch_request_token=lambda: None,
            save_request_token=lambda token: token,
        )
        oauth.register("dev", **client_kwargs)
        assert oauth.dev.name == "dev"
        assert oauth.dev.client_id == "dev"

        oauth = OAuth(app, cache=SimpleCache())
        oauth.register("dev", **client_kwargs)
        assert oauth.dev.name == "dev"
        assert oauth.dev.client_id == "dev"

    def test_oauth1_authorize_cache(self):
        app = Flask(__name__)
        app.secret_key = "!"
        cache = SimpleCache()
        oauth = OAuth(app, cache=cache)

        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            request_token_url="https://i.b/reqeust-token",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        with app.test_request_context():
            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(
                    "oauth_token=foo&oauth_verifier=baz"
                )
                resp = client.authorize_redirect("https://b.com/bar")
                assert resp.status_code == 302
                url = resp.headers.get("Location")
                assert "oauth_token=foo" in url

        with app.test_request_context("/?oauth_token=foo"):
            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(
                    "oauth_token=a&oauth_token_secret=b"
                )
                token = client.authorize_access_token()
                assert token["oauth_token"] == "a"

    def test_oauth1_authorize_session(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            request_token_url="https://i.b/reqeust-token",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        with app.test_request_context():
            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(
                    "oauth_token=foo&oauth_verifier=baz"
                )
                resp = client.authorize_redirect("https://b.com/bar")
                assert resp.status_code == 302
                url = resp.headers.get("Location")
                assert "oauth_token=foo" in url
                data = session["_state_dev_foo"]

        with app.test_request_context("/?oauth_token=foo"):
            session["_state_dev_foo"] = data
            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(
                    "oauth_token=a&oauth_token_secret=b"
                )
                token = client.authorize_access_token()
                assert token["oauth_token"] == "a"

    def test_register_oauth2_remote_app(self):
        app = Flask(__name__)
        oauth = OAuth(app)
        oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            refresh_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            update_token=lambda name: "hi",
        )
        assert oauth.dev.name == "dev"
        session = oauth.dev._get_oauth_client()
        assert session.update_token is not None

    def test_oauth2_authorize(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        with app.test_request_context():
            resp = client.authorize_redirect("https://b.com/bar")
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "state=" in url
            state = dict(url_decode(urlparse.urlparse(url).query))["state"]
            assert state is not None
            data = session[f"_state_dev_{state}"]

        with app.test_request_context(path=f"/?code=a&state={state}"):
            # session is cleared in tests
            session[f"_state_dev_{state}"] = data

            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(get_bearer_token())
                token = client.authorize_access_token()
                assert token["access_token"] == "a"

        with app.test_request_context():
            assert client.token is None

    def test_oauth2_authorize_access_denied(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        with app.test_request_context(
            path="/?error=access_denied&error_description=Not+Allowed"
        ):
            # session is cleared in tests
            with mock.patch("requests.sessions.Session.send"):
                with pytest.raises(OAuthError):
                    client.authorize_access_token()

    def test_oauth2_authorize_via_custom_client(self):
        class CustomRemoteApp(FlaskOAuth2App):
            OAUTH_APP_CONFIG = {"authorize_url": "https://i.b/custom"}

        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            client_cls=CustomRemoteApp,
        )
        with app.test_request_context():
            resp = client.authorize_redirect("https://b.com/bar")
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert url.startswith("https://i.b/custom?")

    def test_oauth2_authorize_with_metadata(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
        )
        with pytest.raises(RuntimeError):
            client.create_authorization_url(None)

        client = oauth.register(
            "dev2",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            server_metadata_url="https://i.b/.well-known/openid-configuration",
        )
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(
                {"authorization_endpoint": "https://i.b/authorize"}
            )

            with app.test_request_context():
                resp = client.authorize_redirect("https://b.com/bar")
                assert resp.status_code == 302

    def test_oauth2_authorize_code_challenge(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            client_kwargs={"code_challenge_method": "S256"},
        )

        with app.test_request_context():
            resp = client.authorize_redirect("https://b.com/bar")
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "code_challenge=" in url
            assert "code_challenge_method=S256" in url

            state = dict(url_decode(urlparse.urlparse(url).query))["state"]
            assert state is not None
            data = session[f"_state_dev_{state}"]

            verifier = data["data"]["code_verifier"]
            assert verifier is not None

        def fake_send(sess, req, **kwargs):
            assert f"code_verifier={verifier}" in req.body
            return mock_send_value(get_bearer_token())

        path = f"/?code=a&state={state}"
        with app.test_request_context(path=path):
            # session is cleared in tests
            session[f"_state_dev_{state}"] = data

            with mock.patch("requests.sessions.Session.send", fake_send):
                token = client.authorize_access_token()
                assert token["access_token"] == "a"

    def test_openid_authorize(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        key = dict(JsonWebKey.import_key("secret", {"kid": "f", "kty": "oct"}))

        client = oauth.register(
            "dev",
            client_id="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
            client_kwargs={"scope": "openid profile"},
            jwks={"keys": [key]},
        )

        with app.test_request_context():
            resp = client.authorize_redirect("https://b.com/bar")
            assert resp.status_code == 302

            url = resp.headers["Location"]
            query_data = dict(url_decode(urlparse.urlparse(url).query))

            state = query_data["state"]
            assert state is not None
            session_data = session[f"_state_dev_{state}"]
            nonce = session_data["data"]["nonce"]
            assert nonce is not None
            assert nonce == query_data["nonce"]

        token = get_bearer_token()
        token["id_token"] = generate_id_token(
            token,
            {"sub": "123"},
            key,
            alg="HS256",
            iss="https://i.b",
            aud="dev",
            exp=3600,
            nonce=query_data["nonce"],
        )
        path = f"/?code=a&state={state}"
        with app.test_request_context(path=path):
            session[f"_state_dev_{state}"] = session_data
            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(token)
                token = client.authorize_access_token()
                assert token["access_token"] == "a"
                assert "userinfo" in token

    def test_oauth2_access_token_with_post(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )
        payload = {"code": "a", "state": "b"}
        with app.test_request_context(data=payload, method="POST"):
            session["_state_dev_b"] = {"data": payload}
            with mock.patch("requests.sessions.Session.send") as send:
                send.return_value = mock_send_value(get_bearer_token())
                token = client.authorize_access_token()
                assert token["access_token"] == "a"

    def test_access_token_with_fetch_token(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth()

        token = get_bearer_token()
        oauth.init_app(app, fetch_token=lambda name: token)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        def fake_send(sess, req, **kwargs):
            auth = req.headers["Authorization"]
            assert auth == "Bearer {}".format(token["access_token"])
            resp = mock.MagicMock()
            resp.text = "hi"
            resp.status_code = 200
            return resp

        with app.test_request_context():
            with mock.patch("requests.sessions.Session.send", fake_send):
                resp = client.get("/api/user")
                assert resp.text == "hi"

                # trigger ctx.authlib_client_oauth_token
                resp = client.get("/api/user")
                assert resp.text == "hi"

    def test_request_with_refresh_token(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth()

        expired_token = {
            "token_type": "Bearer",
            "access_token": "expired-a",
            "refresh_token": "expired-b",
            "expires_in": "3600",
            "expires_at": 1566465749,
        }
        oauth.init_app(app, fetch_token=lambda name: expired_token)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            refresh_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        def fake_send(sess, req, **kwargs):
            if req.url == "https://i.b/token":
                auth = req.headers["Authorization"]
                assert "Basic" in auth
                resp = mock.MagicMock()
                resp.json = get_bearer_token
                resp.status_code = 200
                return resp

            resp = mock.MagicMock()
            resp.text = "hi"
            resp.status_code = 200
            return resp

        with app.test_request_context():
            with mock.patch("requests.sessions.Session.send", fake_send):
                resp = client.get("/api/user", token=expired_token)
                assert resp.text == "hi"

    def test_request_without_token(self):
        app = Flask(__name__)
        app.secret_key = "!"
        oauth = OAuth(app)
        client = oauth.register(
            "dev",
            client_id="dev",
            client_secret="dev",
            api_base_url="https://i.b/api",
            access_token_url="https://i.b/token",
            authorize_url="https://i.b/authorize",
        )

        def fake_send(sess, req, **kwargs):
            auth = req.headers.get("Authorization")
            assert auth is None
            resp = mock.MagicMock()
            resp.text = "hi"
            resp.status_code = 200
            return resp

        with app.test_request_context():
            with mock.patch("requests.sessions.Session.send", fake_send):
                resp = client.get("/api/user", withhold_token=True)
                assert resp.text == "hi"
                with pytest.raises(OAuthError):
                    client.get("https://i.b/api/user")
