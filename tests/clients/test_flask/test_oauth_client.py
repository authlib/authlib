import time
from unittest import mock

import pytest
from cachelib import SimpleCache
from flask import Flask
from flask import session
from joserfc import jwk
from joserfc import jwt

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.base_client import MismatchingIssuerError
from authlib.integrations.flask_client import FlaskOAuth2App
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client import OAuthError
from authlib.oauth2.rfc6749.errors import MissingCodeException
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oidc.core.grants.util import create_half_hash
from tests.util import HMAC_SECRET

from ..util import get_bearer_token
from ..util import mock_send_value


def test_register_remote_app():
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


def test_register_conf_from_app():
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


def test_register_with_overwrite():
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


def test_init_app_later():
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


def test_init_app_params():
    app = Flask(__name__)
    oauth = OAuth()
    oauth.init_app(app, SimpleCache())
    assert oauth.cache is not None
    assert oauth.update_token is None

    oauth.init_app(app, update_token=lambda o: o)
    assert oauth.update_token is not None


def test_create_client():
    app = Flask(__name__)
    oauth = OAuth(app)
    assert oauth.create_client("dev") is None
    oauth.register("dev", client_id="dev")
    assert oauth.create_client("dev") is not None


def test_register_again():
    """Registering a name again replaces the remote application."""
    app = Flask(__name__)
    oauth = OAuth(app)
    oauth.register("dev", client_id="dev-1")
    assert oauth.dev.client_id == "dev-1"

    client = oauth.register("dev", client_id="dev-2")
    assert client.client_id == "dev-2"
    assert oauth.dev.client_id == "dev-2"
    assert oauth.create_client("dev").client_id == "dev-2"


def test_register_again_before_init_app():
    """Registering a name again before init_app replaces the remote application."""
    oauth = OAuth()
    oauth.register("dev", client_id="dev-1")
    remote = oauth.register("dev", client_id="dev-2")
    oauth.init_app(Flask(__name__))
    assert remote.client_id == "dev-2"


def test_remove_client():
    """A removed remote application is no longer available."""
    app = Flask(__name__)
    oauth = OAuth(app)
    oauth.register("dev", client_id="dev")
    assert oauth.dev.client_id == "dev"

    oauth.remove_client("dev")
    assert oauth.create_client("dev") is None
    with pytest.raises(AttributeError):
        oauth.dev  # noqa:B018

    with pytest.raises(KeyError):
        oauth.remove_client("dev")


def test_remove_client_before_init_app():
    """A remote application can be removed before it is created."""
    oauth = OAuth()
    oauth.register("dev", client_id="dev")
    oauth.remove_client("dev")
    oauth.init_app(Flask(__name__))
    assert oauth.create_client("dev") is None


def test_custom_client_config_is_not_shared():
    """Registering a custom client class does not change its OAUTH_APP_CONFIG."""

    class CustomRemoteApp(FlaskOAuth2App):
        OAUTH_APP_CONFIG = {"authorize_url": "https://provider.test/custom"}

    app = Flask(__name__)
    oauth = OAuth(app)
    oauth.register("dev-1", client_id="dev-1", client_cls=CustomRemoteApp)
    oauth.register("dev-2", client_id="dev-2", client_cls=CustomRemoteApp)
    assert CustomRemoteApp.OAUTH_APP_CONFIG == {
        "authorize_url": "https://provider.test/custom"
    }
    assert oauth.create_client("dev-1").client_id == "dev-1"

    client = oauth.register("dev-1", client_id="dev-3", client_cls=CustomRemoteApp)
    assert isinstance(client, CustomRemoteApp)
    assert client.client_id == "dev-3"


def test_overwrite_does_not_change_registered_dicts():
    """Framework config does not change the dicts given to register."""

    class CustomRemoteApp(FlaskOAuth2App):
        OAUTH_APP_CONFIG = {"authorize_params": {"foo": "class"}}

    app = Flask(__name__)
    app.config["DEV_AUTHORIZE_PARAMS"] = {"foo": "config"}
    oauth = OAuth(app)
    access_token_params = {"foo": "register"}
    oauth.register(
        "dev",
        overwrite=True,
        client_cls=CustomRemoteApp,
        access_token_params=access_token_params,
    )
    assert oauth.dev.authorize_params == {"foo": "config"}
    assert CustomRemoteApp.OAUTH_APP_CONFIG["authorize_params"] == {"foo": "class"}
    assert access_token_params == {"foo": "register"}


def test_register_oauth1_remote_app():
    app = Flask(__name__)
    oauth = OAuth(app)
    client_kwargs = dict(
        client_id="dev",
        client_secret="dev",
        request_token_url="https://provider.test/request-token",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
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


def test_oauth1_authorize_cache():
    app = Flask(__name__)
    app.secret_key = "!"
    cache = SimpleCache()
    oauth = OAuth(app, cache=cache)

    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        request_token_url="https://provider.test/request-token",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value("oauth_token=foo&oauth_verifier=baz")
            resp = client.authorize_redirect("https://client.test/callback")
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "oauth_token=foo" in url
            session_data = session["_state_dev_foo"]
            assert "exp" in session_data
            assert "data" not in session_data

    with app.test_request_context("/?oauth_token=foo"):
        with mock.patch("requests.sessions.Session.send") as send:
            session["_state_dev_foo"] = session_data
            send.return_value = mock_send_value("oauth_token=a&oauth_token_secret=b")
            token = client.authorize_access_token()
            assert token["oauth_token"] == "a"


def test_oauth1_authorize_session():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        request_token_url="https://provider.test/request-token",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value("oauth_token=foo&oauth_verifier=baz")
            resp = client.authorize_redirect("https://client.test/callback")
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "oauth_token=foo" in url
            data = session["_state_dev_foo"]

    with app.test_request_context("/?oauth_token=foo"):
        session["_state_dev_foo"] = data
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value("oauth_token=a&oauth_token_secret=b")
            token = client.authorize_access_token()
            assert token["oauth_token"] == "a"


def test_register_oauth2_remote_app():
    app = Flask(__name__)
    oauth = OAuth(app)
    oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        refresh_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        update_token=lambda name: "hi",
    )
    assert oauth.dev.name == "dev"
    session = oauth.dev._get_oauth_client()
    assert session.update_token is not None


def test_oauth2_authorize_cache():
    app = Flask(__name__)
    app.secret_key = "!"
    cache = SimpleCache()
    oauth = OAuth(app, cache=cache)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )
    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
        assert resp.status_code == 302
        url = resp.headers.get("Location")
        assert "state=" in url
        state = dict(url_decode(urlparse.urlparse(url).query))["state"]
        assert state is not None
        session_data = session[f"_state_dev_{state}"]
        assert "exp" in session_data
        assert "data" not in session_data

    with app.test_request_context(path=f"/?code=a&state={state}"):
        # session is cleared in tests
        session[f"_state_dev_{state}"] = session_data

        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
            assert token["access_token"] == "a"

    with app.test_request_context():
        assert client.token is None


class StrictCache(SimpleCache):
    def delete(self, key):
        raise ValueError(f"Invalid cache key: {key!r}")


def test_oauth2_authorize_unknown_state_with_cache():
    """An unknown state is refused, and never reaches the cache."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app, cache=StrictCache())
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    with app.test_request_context(path="/?code=a&state=a%20b"):
        with pytest.raises(OAuthError, match="mismatching_state"):
            client.authorize_access_token()


def test_oauth2_authorize_session():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
        assert resp.status_code == 302
        url = resp.headers.get("Location")
        assert "state=" in url
        state = dict(url_decode(urlparse.urlparse(url).query))["state"]
        assert state is not None
        session_data = session[f"_state_dev_{state}"]
        assert "exp" in session_data
        assert "data" in session_data

    with app.test_request_context(path=f"/?code=a&state={state}"):
        # session is cleared in tests
        session[f"_state_dev_{state}"] = session_data

        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
            assert token["access_token"] == "a"

    with app.test_request_context():
        assert client.token is None


def test_oauth2_authorize_access_denied():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    with app.test_request_context(
        path="/?error=access_denied&error_description=Not+Allowed"
    ):
        # session is cleared in tests
        with mock.patch("requests.sessions.Session.send"):
            with pytest.raises(OAuthError):
                client.authorize_access_token()


def test_oauth2_authorize_via_custom_client():
    class CustomRemoteApp(FlaskOAuth2App):
        OAUTH_APP_CONFIG = {"authorize_url": "https://provider.test/custom"}

    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        client_cls=CustomRemoteApp,
    )
    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
        assert resp.status_code == 302
        url = resp.headers.get("Location")
        assert url.startswith("https://provider.test/custom?")


def test_oauth2_fetch_metadata():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )
    with mock.patch("requests.sessions.Session.send") as send:

        def check_request(req, **kwargs):
            assert "Authlib/" in req.headers.get("user-agent", "")
            if req.url == "https://provider.test/.well-known/openid-configuration":
                return mock_send_value(
                    {
                        "issuer": "https://provider.test",
                        "authorization_endpoint": "https://provider.test/authorize",
                        "jwks_uri": "https://provider.test/.well-known/keys",
                    }
                )
            if req.url == "https://provider.test/.well-known/keys":
                return mock_send_value({"keys": []})
            return mock.DEFAULT

        send.side_effect = check_request

        with app.test_request_context():
            client.fetch_jwk_set()

        assert send.call_count == 2


def test_oauth2_client_kwargs_headers():
    """The client_kwargs headers are sent with the server metadata, JWKS and
    token requests."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={"headers": {"X-Api-Key": "secret"}},
    )
    sent = []

    def fake_send(sess, req, **kwargs):
        sent.append(req)
        if req.url.endswith("/openid-configuration"):
            return mock_send_value(
                {
                    "issuer": "https://provider.test",
                    "token_endpoint": "https://provider.test/token",
                    "jwks_uri": "https://provider.test/jwks",
                }
            )

        if req.url.endswith("/jwks"):
            return mock_send_value({"keys": []})

        return mock_send_value(get_bearer_token())

    with mock.patch("requests.sessions.Session.send", fake_send):
        client.fetch_jwk_set()
        client.fetch_access_token(code="a")

    assert len(sent) == 3
    assert all(req.headers["X-Api-Key"] == "secret" for req in sent)
    assert all(req.headers["User-Agent"] == client._user_agent for req in sent)


def test_oauth2_authorize_with_metadata():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
    )
    with pytest.raises(RuntimeError):
        client.create_authorization_url(None)

    client = oauth.register(
        "dev2",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(
            {
                "issuer": "https://provider.test",
                "authorization_endpoint": "https://provider.test/authorize",
            }
        )

        with app.test_request_context():
            resp = client.authorize_redirect("https://client.test/callback")
            assert resp.status_code == 302


def test_oauth2_metadata_does_not_configure_client():
    """The fetched server metadata does not change the client settings."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
        client_kwargs={"scope": "openid", "verify": "/ca.pem"},
    )
    metadata = {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/authorize",
        "client_id": "other",
        "scope": "admin",
        "hooks": {"key": True},
        "verify": False,
    }

    def fake_send(sess, req, **kwargs):
        if req.url == "https://provider.test/.well-known/openid-configuration":
            return mock_send_value(metadata)

        assert kwargs["verify"] == "/ca.pem"
        return mock_send_value({"sub": "123"})

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            rv = client.create_authorization_url("https://client.test/callback")
            resp = client.get("user", token=get_bearer_token())

    params = dict(url_decode(urlparse.urlparse(rv["url"]).query))
    assert params["client_id"] == "dev"
    assert params["scope"] == "openid"
    assert resp.json() == {"sub": "123"}
    assert client.server_metadata["scope"] == "admin"


def test_oauth2_refresh_token_with_metadata_token_endpoint():
    """An expired token is refreshed at the token endpoint of the metadata."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )
    expired_token = {
        "token_type": "Bearer",
        "access_token": "expired-a",
        "refresh_token": "expired-b",
        "expires_at": 1566465749,
    }
    urls = []

    def fake_send(sess, req, **kwargs):
        urls.append(req.url)
        if req.url == "https://provider.test/.well-known/openid-configuration":
            return mock_send_value(
                {
                    "issuer": "https://provider.test",
                    "token_endpoint": "https://provider.test/token",
                }
            )

        if req.url == "https://provider.test/token":
            return mock_send_value(get_bearer_token())

        return mock_send_value({"sub": "123"})

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            client.get("user", token=expired_token)

    assert urls[1] == "https://provider.test/token"


def load_metadata(metadata_url, metadata_issuer, **kwargs):
    """Register a client and load its server metadata."""
    app = Flask(__name__)
    oauth = OAuth(app)
    client = oauth.register(
        "dev", client_id="dev", server_metadata_url=metadata_url, **kwargs
    )
    metadata = {"authorization_endpoint": "https://provider.test/authorize"}
    if metadata_issuer:
        metadata["issuer"] = metadata_issuer

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)
        client.load_server_metadata()

    return client


@pytest.mark.parametrize(
    "metadata_url,metadata_issuer",
    [
        (
            "https://provider.test/.well-known/openid-configuration",
            "https://provider.test",
        ),
        (
            "https://provider.test/.well-known/openid-configuration",
            "https://provider.test/",
        ),
        (
            "https://provider.test/realms/x/.well-known/openid-configuration",
            "https://provider.test/realms/x",
        ),
        (
            "https://provider.test/.well-known/openid-configuration/tenant",
            "https://provider.test/tenant",
        ),
        (
            "https://provider.test/.well-known/oauth-authorization-server",
            "https://provider.test",
        ),
        (
            "https://provider.test/.well-known/oauth-authorization-server/tenant",
            "https://provider.test/tenant",
        ),
        (
            "https://provider.test/realms/x/.well-known/openid-configuration",
            "https://provider.test/realms/x/",
        ),
        ("https://provider.test/metadata.json", "https://other.test"),
    ],
)
def test_oauth2_metadata_issuer(metadata_url, metadata_issuer):
    """The server metadata is accepted when its issuer matches the metadata
    URL, or when the URL has no well-known path."""
    client = load_metadata(metadata_url, metadata_issuer)
    assert client.server_metadata["issuer"] == metadata_issuer


@pytest.mark.parametrize(
    "metadata_url,metadata_issuer",
    [
        (
            "https://provider.test/.well-known/openid-configuration",
            "https://attacker.test",
        ),
        ("https://provider.test/.well-known/openid-configuration", None),
        (
            "https://provider.test/realms/x/.well-known/openid-configuration",
            "https://provider.test/realms/other",
        ),
        (
            "https://provider.test/.well-known/oauth-authorization-server/tenant",
            "https://provider.test",
        ),
        (
            "https://provider.test/.well-known/openid-configuration?p=policy",
            "https://provider.test",
        ),
    ],
)
def test_oauth2_metadata_issuer_mismatch(metadata_url, metadata_issuer):
    """The server metadata is refused when its issuer does not match the
    metadata URL (RFC 8414 §3.3, OpenID Connect Discovery §4.3)."""
    with pytest.raises(MismatchingIssuerError):
        load_metadata(metadata_url, metadata_issuer)


def test_oauth2_metadata_issuer_from_config():
    """The issuer can be set in the application config."""
    app = Flask(__name__)
    app.config.update(
        {
            "DEV_CLIENT_ID": "dev",
            "DEV_ISSUER": "http://localhost:8080/realms/x",
            "DEV_SERVER_METADATA_URL": (
                "http://keycloak:8080/realms/x/.well-known/openid-configuration"
            ),
        }
    )
    oauth = OAuth(app)
    client = oauth.register("dev")
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(
            {"issuer": "http://localhost:8080/realms/x"}
        )
        client.load_server_metadata()

    assert client.server_metadata["issuer"] == "http://localhost:8080/realms/x"


def test_oauth2_metadata_issuer_not_cached():
    """Refused server metadata is not kept."""
    app = Flask(__name__)
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value({"issuer": "https://attacker.test"})
        with pytest.raises(MismatchingIssuerError):
            client.load_server_metadata()

        with pytest.raises(MismatchingIssuerError):
            client.load_server_metadata()

    assert send.call_count == 2
    assert "_loaded_at" not in client.server_metadata


def test_oauth2_metadata_registered_issuer():
    """The issuer given to register replaces the issuer of the metadata URL."""
    issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
    client = load_metadata(
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
        issuer,
        issuer=issuer,
    )
    assert client.server_metadata["issuer"] == issuer

    with pytest.raises(MismatchingIssuerError):
        load_metadata(
            "https://provider.test/.well-known/openid-configuration",
            "https://provider.test/",
            issuer="https://provider.test",
        )


@pytest.mark.parametrize("method", ["S256", "plain"])
def test_oauth2_authorize_code_challenge(method):
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={"code_challenge_method": method},
    )

    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
        assert resp.status_code == 302
        url = resp.headers.get("Location")
        params = dict(url_decode(urlparse.urlparse(url).query))
        assert params["code_challenge_method"] == method

        state = params["state"]
        assert state is not None
        data = session[f"_state_dev_{state}"]

        verifier = data["data"]["code_verifier"]
        assert verifier is not None
        if method == "plain":
            assert params["code_challenge"] == verifier
        else:
            assert params["code_challenge"] == create_s256_code_challenge(verifier)

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


def test_openid_authorize():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    key = jwk.import_key(HMAC_SECRET, "oct")

    client = oauth.register(
        "dev",
        client_id="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
        client_kwargs={"scope": "openid profile"},
        jwks={"keys": [key.as_dict()]},
        id_token_signing_alg_values_supported=["HS256"],
    )

    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
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
    now = int(time.time())
    claims = {
        "sub": "123",
        "iss": "https://provider.test",
        "aud": "dev",
        "iat": now,
        "auth_time": now,
        "exp": now + 3600,
        "nonce": query_data["nonce"],
        "at_hash": create_half_hash(token["access_token"], "HS256").decode("utf-8"),
    }
    id_token = jwt.encode({"alg": "HS256"}, claims, key)
    token["id_token"] = id_token
    path = f"/?code=a&state={state}"
    with app.test_request_context(path=path):
        session[f"_state_dev_{state}"] = session_data
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(token)
            token = client.authorize_access_token()
            assert token["access_token"] == "a"
            assert "userinfo" in token


def test_oauth2_access_token_with_post():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )
    payload = {"code": "a", "state": "b"}
    with app.test_request_context(data=payload, method="POST"):
        session["_state_dev_b"] = {"data": payload}
        with mock.patch("requests.sessions.Session.send") as send:
            send.return_value = mock_send_value(get_bearer_token())
            token = client.authorize_access_token()
            assert token["access_token"] == "a"


def test_oauth2_access_denied_with_post():
    """An error response sent with form_post raises an OAuthError."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )
    payload = {
        "error": "access_denied",
        "error_description": "Not Allowed",
        "error_uri": "https://provider.test/help",
    }
    with app.test_request_context(data=payload, method="POST"):
        with mock.patch("requests.sessions.Session.send") as send:
            with pytest.raises(OAuthError) as exc_info:
                client.authorize_access_token()

            assert exc_info.value.error == "access_denied"
            assert exc_info.value.description == "Not Allowed"
            assert exc_info.value.uri == "https://provider.test/help"
            send.assert_not_called()


def test_access_token_with_fetch_token():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth()

    token = get_bearer_token()
    oauth.init_app(app, fetch_token=lambda name: token)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
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


def test_request_with_refresh_token():
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
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        refresh_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    def fake_send(sess, req, **kwargs):
        if req.url == "https://provider.test/token":
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


def test_request_with_expired_token_sends_access_token_params():
    """A new token fetched on expiry is requested with access_token_params."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        access_token_params={"audience": "api"},
        client_kwargs={"grant_type": "client_credentials"},
    )
    expired_token = {
        "token_type": "Bearer",
        "access_token": "expired",
        "expires_at": 1566465749,
    }
    bodies = []

    def fake_send(sess, req, **kwargs):
        bodies.append(req.body)
        resp = mock.MagicMock()
        resp.json = get_bearer_token
        resp.status_code = 200
        return resp

    with app.test_request_context():
        with mock.patch("requests.sessions.Session.send", fake_send):
            client.get("/api/user", token=expired_token)

    assert "audience=api" in bodies[0]


def test_client_kwargs_access_token_params():
    """The access_token_params of client_kwargs are kept."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        client_kwargs={"access_token_params": {"audience": "api"}},
    )

    session = client._get_oauth_client()

    assert session.access_token_params == {"audience": "api"}


def test_request_without_token():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
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
                client.get("https://resource.test/api/user")


def test_oauth2_authorize_missing_code():
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://resource.test/api",
        access_token_url="https://provider.test/token",
        authorize_url="https://provider.test/authorize",
    )

    with app.test_request_context():
        resp = client.authorize_redirect("https://client.test/callback")
        state = dict(url_decode(urlparse.urlparse(resp.headers["Location"]).query))[
            "state"
        ]
        session_data = session[f"_state_dev_{state}"]

    # Test missing code parameter
    with app.test_request_context(path=f"/?state={state}"):
        session[f"_state_dev_{state}"] = session_data
        with pytest.raises(MissingCodeException) as exc_info:
            client.authorize_access_token()
        assert exc_info.value.error == "missing_code"


def test_logout_redirect_with_metadata():
    """Test logout_redirect generates correct URL with state stored in session."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": "https://provider.test",
        "end_session_endpoint": "https://provider.test/logout",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            resp = client.logout_redirect(
                post_logout_redirect_uri="https://client.test/logged-out",
                id_token_hint="fake.id.token",
            )
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "https://provider.test/logout" in url
            assert "id_token_hint=fake.id.token" in url
            assert (
                "post_logout_redirect_uri=https%3A%2F%2Fclient.test%2Flogged-out" in url
            )
            assert "state=" in url

            # Verify state is stored in session
            params = dict(url_decode(urlparse.urlparse(url).query))
            state = params["state"]
            assert f"_state_dev_{state}" in session


def test_logout_redirect_without_redirect_uri():
    """Test logout_redirect omits state when no post_logout_redirect_uri is provided."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": "https://provider.test",
        "end_session_endpoint": "https://provider.test/logout",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            resp = client.logout_redirect(id_token_hint="fake.id.token")
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "https://provider.test/logout" in url
            assert "id_token_hint=fake.id.token" in url
            assert "post_logout_redirect_uri" not in url
            assert "state" not in url

            # No state stored when no redirect_uri
            assert not any(k.startswith("_state_dev_") for k in session.keys())


def test_logout_redirect_with_extra_params():
    """Test logout_redirect includes optional params: client_id, logout_hint, ui_locales."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": "https://provider.test",
        "end_session_endpoint": "https://provider.test/logout",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            resp = client.logout_redirect(
                post_logout_redirect_uri="https://client.test/logged-out",
                client_id="dev",
                logout_hint="user@example.com",
                ui_locales="fr",
            )
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "client_id=dev" in url
            assert "logout_hint=user%40example.com" in url
            assert "ui_locales=fr" in url


def test_logout_redirect_with_custom_state():
    """Test logout_redirect uses a custom state value when provided."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": "https://provider.test",
        "end_session_endpoint": "https://provider.test/logout",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            resp = client.logout_redirect(
                post_logout_redirect_uri="https://client.test/logged-out",
                state="custom-state-123",
            )
            assert resp.status_code == 302
            url = resp.headers.get("Location")
            assert "state=custom-state-123" in url


def test_logout_redirect_missing_endpoint():
    """Test logout_redirect raises RuntimeError when end_session_endpoint is missing."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    # Metadata without end_session_endpoint
    metadata = {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/authorize",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            with pytest.raises(RuntimeError, match='Missing "end_session_endpoint"'):
                client.logout_redirect()


def test_create_logout_url_directly():
    """Test create_logout_url returns URL and state without performing redirect."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": "https://provider.test",
        "end_session_endpoint": "https://provider.test/logout",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            result = client.create_logout_url(
                post_logout_redirect_uri="https://client.test/logged-out",
                id_token_hint="fake.id.token",
            )
            assert "url" in result
            assert "state" in result
            assert result["state"] is not None
            assert "https://provider.test/logout" in result["url"]


def test_validate_logout_response():
    """Test validate_logout_response verifies state and returns stored data."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    metadata = {
        "issuer": "https://provider.test",
        "end_session_endpoint": "https://provider.test/logout",
    }

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(metadata)

        with app.test_request_context():
            resp = client.logout_redirect(
                post_logout_redirect_uri="https://client.test/logged-out",
            )
            url = resp.headers.get("Location")
            params = dict(url_decode(urlparse.urlparse(url).query))
            state = params["state"]
            session_data = session[f"_state_dev_{state}"]

        with app.test_request_context(path=f"/?state={state}"):
            session[f"_state_dev_{state}"] = session_data
            state_data = client.validate_logout_response()
            assert (
                state_data["post_logout_redirect_uri"]
                == "https://client.test/logged-out"
            )
            # State should be cleared from session
            assert f"_state_dev_{state}" not in session


def test_validate_logout_response_missing_state():
    """Test validate_logout_response raises OAuthError when state is missing."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    with app.test_request_context(path="/"):
        with pytest.raises(OAuthError, match='Missing "state" parameter'):
            client.validate_logout_response()


def test_validate_logout_response_invalid_state():
    """Test validate_logout_response raises OAuthError when state is invalid."""
    app = Flask(__name__)
    app.secret_key = "!"
    oauth = OAuth(app)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        server_metadata_url="https://provider.test/.well-known/openid-configuration",
    )

    with app.test_request_context(path="/?state=invalid-state"):
        with pytest.raises(OAuthError, match='Invalid "state" parameter'):
            client.validate_logout_response()
