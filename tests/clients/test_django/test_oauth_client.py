from unittest import mock

import pytest
from django.test import override_settings

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.django_client import OAuth
from authlib.integrations.django_client import OAuthError
from authlib.jose import JsonWebKey
from authlib.oidc.core.grants.util import generate_id_token

from ..util import get_bearer_token
from ..util import mock_send_value

dev_client = {"client_id": "dev-key", "client_secret": "dev-secret"}


def test_register_remote_app():
    oauth = OAuth()
    with pytest.raises(AttributeError):
        oauth.dev  # noqa:B018

    oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        request_token_url="https://i.b/reqeust-token",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
    )
    assert oauth.dev.name == "dev"
    assert oauth.dev.client_id == "dev"


def test_register_with_overwrite():
    oauth = OAuth()
    oauth.register(
        "dev_overwrite",
        overwrite=True,
        client_id="dev",
        client_secret="dev",
        request_token_url="https://i.b/reqeust-token",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        access_token_params={"foo": "foo"},
        authorize_url="https://i.b/authorize",
    )
    assert oauth.dev_overwrite.client_id == "dev-client-id"
    assert oauth.dev_overwrite.access_token_params["foo"] == "foo-1"


@override_settings(AUTHLIB_OAUTH_CLIENTS={"dev": dev_client})
def test_register_from_settings():
    oauth = OAuth()
    oauth.register("dev")
    assert oauth.dev.client_id == "dev-key"
    assert oauth.dev.client_secret == "dev-secret"


def test_oauth1_authorize(factory):
    request = factory.get("/login")
    request.session = factory.session

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        request_token_url="https://i.b/reqeust-token",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
    )

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value("oauth_token=foo&oauth_verifier=baz")

        resp = client.authorize_redirect(request)
        assert resp.status_code == 302
        url = resp.get("Location")
        assert "oauth_token=foo" in url

    request2 = factory.get(url)
    request2.session = request.session
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value("oauth_token=a&oauth_token_secret=b")
        token = client.authorize_access_token(request2)
        assert token["oauth_token"] == "a"


def test_oauth2_authorize(factory):
    request = factory.get("/login")
    request.session = factory.session

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
    )
    rv = client.authorize_redirect(request, "https://a.b/c")
    assert rv.status_code == 302
    url = rv.get("Location")
    assert "state=" in url
    state = dict(url_decode(urlparse.urlparse(url).query))["state"]

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(get_bearer_token())
        request2 = factory.get(f"/authorize?state={state}&code=foo")
        request2.session = request.session

        token = client.authorize_access_token(request2)
        assert token["access_token"] == "a"


def test_oauth2_authorize_access_denied(factory):
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
    )

    with mock.patch("requests.sessions.Session.send"):
        request = factory.get("/?error=access_denied&error_description=Not+Allowed")
        request.session = factory.session
        with pytest.raises(OAuthError):
            client.authorize_access_token(request)


def test_oauth2_authorize_code_challenge(factory):
    request = factory.get("/login")
    request.session = factory.session

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={"code_challenge_method": "S256"},
    )
    rv = client.authorize_redirect(request, "https://a.b/c")
    assert rv.status_code == 302
    url = rv.get("Location")
    assert "state=" in url
    assert "code_challenge=" in url

    state = dict(url_decode(urlparse.urlparse(url).query))["state"]
    state_data = request.session[f"_state_dev_{state}"]["data"]
    verifier = state_data["code_verifier"]

    def fake_send(sess, req, **kwargs):
        assert f"code_verifier={verifier}" in req.body
        return mock_send_value(get_bearer_token())

    with mock.patch("requests.sessions.Session.send", fake_send):
        request2 = factory.get(f"/authorize?state={state}&code=foo")
        request2.session = request.session
        token = client.authorize_access_token(request2)
        assert token["access_token"] == "a"


def test_oauth2_authorize_code_verifier(factory):
    request = factory.get("/login")
    request.session = factory.session

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={"code_challenge_method": "S256"},
    )
    state = "foo"
    code_verifier = "bar"
    rv = client.authorize_redirect(
        request, "https://a.b/c", state=state, code_verifier=code_verifier
    )
    assert rv.status_code == 302
    url = rv.get("Location")
    assert "state=" in url
    assert "code_challenge=" in url

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(get_bearer_token())

        request2 = factory.get(f"/authorize?state={state}&code=foo")
        request2.session = request.session

        token = client.authorize_access_token(request2)
        assert token["access_token"] == "a"


def test_openid_authorize(factory):
    request = factory.get("/login")
    request.session = factory.session
    secret_key = JsonWebKey.import_key("secret", {"kty": "oct", "kid": "f"})

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        jwks={"keys": [secret_key.as_dict()]},
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        client_kwargs={"scope": "openid profile"},
    )

    resp = client.authorize_redirect(request, "https://b.com/bar")
    assert resp.status_code == 302
    url = resp.get("Location")
    assert "nonce=" in url
    query_data = dict(url_decode(urlparse.urlparse(url).query))

    token = get_bearer_token()
    token["id_token"] = generate_id_token(
        token,
        {"sub": "123"},
        secret_key,
        alg="HS256",
        iss="https://i.b",
        aud="dev",
        exp=3600,
        nonce=query_data["nonce"],
    )
    state = query_data["state"]
    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(token)

        request2 = factory.get(f"/authorize?state={state}&code=foo")
        request2.session = request.session

        token = client.authorize_access_token(request2)
        assert token["access_token"] == "a"
        assert "userinfo" in token
        assert token["userinfo"]["sub"] == "123"


def test_oauth2_access_token_with_post(factory):
    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
    )
    payload = {"code": "a", "state": "b"}

    with mock.patch("requests.sessions.Session.send") as send:
        send.return_value = mock_send_value(get_bearer_token())
        request = factory.post("/token", data=payload)
        request.session = factory.session
        request.session["_state_dev_b"] = {"data": {}}
        token = client.authorize_access_token(request)
        assert token["access_token"] == "a"


def test_with_fetch_token_in_oauth(factory):
    def fetch_token(name, request):
        return {"access_token": name, "token_type": "bearer"}

    oauth = OAuth(fetch_token=fetch_token)
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
    )

    def fake_send(sess, req, **kwargs):
        assert sess.token["access_token"] == "dev"
        return mock_send_value(get_bearer_token())

    with mock.patch("requests.sessions.Session.send", fake_send):
        request = factory.get("/login")
        client.get("/user", request=request)


def test_with_fetch_token_in_register(factory):
    def fetch_token(request):
        return {"access_token": "dev", "token_type": "bearer"}

    oauth = OAuth()
    client = oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev",
        api_base_url="https://i.b/api",
        access_token_url="https://i.b/token",
        authorize_url="https://i.b/authorize",
        fetch_token=fetch_token,
    )

    def fake_send(sess, req, **kwargs):
        assert sess.token["access_token"] == "dev"
        return mock_send_value(get_bearer_token())

    with mock.patch("requests.sessions.Session.send", fake_send):
        request = factory.get("/login")
        client.get("/user", request=request)


def test_request_without_token():
    oauth = OAuth()
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

    with mock.patch("requests.sessions.Session.send", fake_send):
        resp = client.get("/api/user", withhold_token=True)
        assert resp.text == "hi"
        with pytest.raises(OAuthError):
            client.get("https://i.b/api/user")
