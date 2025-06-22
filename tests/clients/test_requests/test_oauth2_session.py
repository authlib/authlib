import time
from copy import deepcopy
from unittest import TestCase
from unittest import mock

import pytest

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_encode
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.requests_client import OAuthError
from authlib.oauth2.rfc6749 import MismatchingStateException
from authlib.oauth2.rfc7523 import ClientSecretJWT
from authlib.oauth2.rfc7523 import PrivateKeyJWT

from ..util import read_key_file


def mock_json_response(payload):
    def fake_send(r, **kwargs):
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.json = lambda: payload
        return resp

    return fake_send


def mock_assertion_response(ctx, session):
    def fake_send(r, **kwargs):
        ctx.assertIn("client_assertion=", r.body)
        ctx.assertIn("client_assertion_type=", r.body)
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.json = lambda: ctx.token
        return resp

    session.send = fake_send


class OAuth2SessionTest(TestCase):
    def setUp(self):
        self.token = {
            "token_type": "Bearer",
            "access_token": "a",
            "refresh_token": "b",
            "expires_in": "3600",
            "expires_at": int(time.time()) + 3600,
        }
        self.client_id = "foo"

    def test_invalid_token_type(self):
        token = {
            "token_type": "invalid",
            "access_token": "a",
            "refresh_token": "b",
            "expires_in": "3600",
            "expires_at": int(time.time()) + 3600,
        }
        with OAuth2Session(self.client_id, token=token) as sess:
            with pytest.raises(OAuthError):
                sess.get("https://i.b")

    def test_add_token_to_header(self):
        token = "Bearer " + self.token["access_token"]

        def verifier(r, **kwargs):
            auth_header = r.headers.get("Authorization", None)
            assert auth_header == token
            resp = mock.MagicMock()
            return resp

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = verifier
        sess.get("https://i.b")

    def test_add_token_to_body(self):
        def verifier(r, **kwargs):
            assert self.token["access_token"] in r.body
            resp = mock.MagicMock()
            return resp

        sess = OAuth2Session(
            client_id=self.client_id, token=self.token, token_placement="body"
        )
        sess.send = verifier
        sess.post("https://i.b")

    def test_add_token_to_uri(self):
        def verifier(r, **kwargs):
            assert self.token["access_token"] in r.url
            resp = mock.MagicMock()
            return resp

        sess = OAuth2Session(
            client_id=self.client_id, token=self.token, token_placement="uri"
        )
        sess.send = verifier
        sess.get("https://i.b")

    def test_create_authorization_url(self):
        url = "https://example.com/authorize?foo=bar"

        sess = OAuth2Session(client_id=self.client_id)
        auth_url, state = sess.create_authorization_url(url)
        assert state in auth_url
        assert self.client_id in auth_url
        assert "response_type=code" in auth_url

        sess = OAuth2Session(client_id=self.client_id, prompt="none")
        auth_url, state = sess.create_authorization_url(
            url, state="foo", redirect_uri="https://i.b", scope="profile"
        )
        assert state == "foo"
        assert "i.b" in auth_url
        assert "profile" in auth_url
        assert "prompt=none" in auth_url

    def test_code_challenge(self):
        sess = OAuth2Session(client_id=self.client_id, code_challenge_method="S256")

        url = "https://example.com/authorize"
        auth_url, _ = sess.create_authorization_url(
            url, code_verifier=generate_token(48)
        )
        assert "code_challenge" in auth_url
        assert "code_challenge_method=S256" in auth_url

    def test_token_from_fragment(self):
        sess = OAuth2Session(self.client_id)
        response_url = "https://i.b/callback#" + url_encode(self.token.items())
        assert sess.token_from_fragment(response_url) == self.token
        token = sess.fetch_token(authorization_response=response_url)
        assert token == self.token

    def test_fetch_token_post(self):
        url = "https://example.com/token"

        def fake_send(r, **kwargs):
            assert "code=v" in r.body
            assert "client_id=" in r.body
            assert "grant_type=authorization_code" in r.body
            resp = mock.MagicMock()
            resp.status_code = 200
            resp.json = lambda: self.token
            return resp

        sess = OAuth2Session(client_id=self.client_id)
        sess.send = fake_send
        assert (
            sess.fetch_token(url, authorization_response="https://i.b/?code=v")
            == self.token
        )

        sess = OAuth2Session(
            client_id=self.client_id,
            token_endpoint_auth_method="none",
        )
        sess.send = fake_send
        token = sess.fetch_token(url, code="v")
        assert token == self.token

        error = {"error": "invalid_request"}
        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.send = mock_json_response(error)
        with pytest.raises(OAuthError):
            sess.fetch_access_token(url)

    def test_fetch_token_get(self):
        url = "https://example.com/token"

        def fake_send(r, **kwargs):
            assert "code=v" in r.url
            assert "grant_type=authorization_code" in r.url
            resp = mock.MagicMock()
            resp.status_code = 200
            resp.json = lambda: self.token
            return resp

        sess = OAuth2Session(client_id=self.client_id)
        sess.send = fake_send
        token = sess.fetch_token(
            url, authorization_response="https://i.b/?code=v", method="GET"
        )
        assert token == self.token

        sess = OAuth2Session(
            client_id=self.client_id,
            token_endpoint_auth_method="none",
        )
        sess.send = fake_send
        token = sess.fetch_token(url, code="v", method="GET")
        assert token == self.token

        token = sess.fetch_token(url + "?q=a", code="v", method="GET")
        assert token == self.token

    def test_token_auth_method_client_secret_post(self):
        url = "https://example.com/token"

        def fake_send(r, **kwargs):
            assert "code=v" in r.body
            assert "client_id=" in r.body
            assert "client_secret=bar" in r.body
            assert "grant_type=authorization_code" in r.body
            resp = mock.MagicMock()
            resp.status_code = 200
            resp.json = lambda: self.token
            return resp

        sess = OAuth2Session(
            client_id=self.client_id,
            client_secret="bar",
            token_endpoint_auth_method="client_secret_post",
        )
        sess.send = fake_send
        token = sess.fetch_token(url, code="v")
        assert token == self.token

    def test_access_token_response_hook(self):
        url = "https://example.com/token"

        def access_token_response_hook(resp):
            assert resp.json() == self.token
            return resp

        sess = OAuth2Session(client_id=self.client_id, token=self.token)
        sess.register_compliance_hook(
            "access_token_response", access_token_response_hook
        )
        sess.send = mock_json_response(self.token)
        assert sess.fetch_token(url) == self.token

    def test_password_grant_type(self):
        url = "https://example.com/token"

        def fake_send(r, **kwargs):
            assert "username=v" in r.body
            assert "grant_type=password" in r.body
            assert "scope=profile" in r.body
            resp = mock.MagicMock()
            resp.status_code = 200
            resp.json = lambda: self.token
            return resp

        sess = OAuth2Session(client_id=self.client_id, scope="profile")
        sess.send = fake_send
        token = sess.fetch_token(url, username="v", password="v")
        assert token == self.token

    def test_client_credentials_type(self):
        url = "https://example.com/token"

        def fake_send(r, **kwargs):
            assert "grant_type=client_credentials" in r.body
            assert "scope=profile" in r.body
            resp = mock.MagicMock()
            resp.status_code = 200
            resp.json = lambda: self.token
            return resp

        sess = OAuth2Session(
            client_id=self.client_id,
            client_secret="v",
            scope="profile",
        )
        sess.send = fake_send
        token = sess.fetch_token(url)
        assert token == self.token

    def test_cleans_previous_token_before_fetching_new_one(self):
        """Makes sure the previous token is cleaned before fetching a new one.
        The reason behind it is that, if the previous token is expired, this
        method shouldn't fail with a TokenExpiredError, since it's attempting
        to get a new one (which shouldn't be expired).
        """
        now = int(time.time())
        new_token = deepcopy(self.token)
        past = now - 7200
        self.token["expires_at"] = past
        new_token["expires_at"] = now + 3600
        url = "https://example.com/token"

        with mock.patch("time.time", lambda: now):
            sess = OAuth2Session(client_id=self.client_id, token=self.token)
            sess.send = mock_json_response(new_token)
            assert sess.fetch_token(url) == new_token

    def test_mis_match_state(self):
        sess = OAuth2Session("foo")
        with pytest.raises(MismatchingStateException):
            sess.fetch_token(
                "https://i.b/token",
                authorization_response="https://i.b/no-state?code=abc",
                state="somestate",
            )

    def test_token_status(self):
        token = dict(access_token="a", token_type="bearer", expires_at=100)
        sess = OAuth2Session("foo", token=token)

        assert sess.token.is_expired

    def test_token_status2(self):
        token = dict(access_token="a", token_type="bearer", expires_in=10)
        sess = OAuth2Session("foo", token=token, leeway=15)

        assert sess.token.is_expired(sess.leeway)

    def test_token_status3(self):
        token = dict(access_token="a", token_type="bearer", expires_in=10)
        sess = OAuth2Session("foo", token=token, leeway=5)

        assert not sess.token.is_expired(sess.leeway)

    def test_token_expired(self):
        token = dict(access_token="a", token_type="bearer", expires_at=100)
        sess = OAuth2Session("foo", token=token)
        with pytest.raises(OAuthError):
            sess.get(
                "https://i.b/token",
            )

    def test_missing_token(self):
        sess = OAuth2Session("foo")
        with pytest.raises(OAuthError):
            sess.get(
                "https://i.b/token",
            )

    def test_register_compliance_hook(self):
        sess = OAuth2Session("foo")
        with pytest.raises(ValueError):
            sess.register_compliance_hook(
                "invalid_hook",
                lambda o: o,
            )

        def protected_request(url, headers, data):
            assert "Authorization" in headers
            return url, headers, data

        sess = OAuth2Session("foo", token=self.token)
        sess.register_compliance_hook(
            "protected_request",
            protected_request,
        )
        sess.send = mock_json_response({"name": "a"})
        sess.get("https://i.b/user")

    def test_auto_refresh_token(self):
        def _update_token(token, refresh_token=None, access_token=None):
            assert refresh_token == "b"
            assert token == self.token

        update_token = mock.Mock(side_effect=_update_token)
        old_token = dict(
            access_token="a", refresh_token="b", token_type="bearer", expires_at=100
        )
        sess = OAuth2Session(
            "foo",
            token=old_token,
            token_endpoint="https://i.b/token",
            update_token=update_token,
        )
        sess.send = mock_json_response(self.token)
        sess.get("https://i.b/user")
        assert update_token.called

    def test_auto_refresh_token2(self):
        def _update_token(token, refresh_token=None, access_token=None):
            assert access_token == "a"
            assert token == self.token

        update_token = mock.Mock(side_effect=_update_token)
        old_token = dict(access_token="a", token_type="bearer", expires_at=100)

        sess = OAuth2Session(
            "foo",
            token=old_token,
            token_endpoint="https://i.b/token",
            grant_type="client_credentials",
        )
        sess.send = mock_json_response(self.token)
        sess.get("https://i.b/user")
        assert not update_token.called

        sess = OAuth2Session(
            "foo",
            token=old_token,
            token_endpoint="https://i.b/token",
            grant_type="client_credentials",
            update_token=update_token,
        )
        sess.send = mock_json_response(self.token)
        sess.get("https://i.b/user")
        assert update_token.called

    def test_revoke_token(self):
        sess = OAuth2Session("a")
        answer = {"status": "ok"}
        sess.send = mock_json_response(answer)
        resp = sess.revoke_token("https://i.b/token", "hi")
        assert resp.json() == answer
        resp = sess.revoke_token(
            "https://i.b/token", "hi", token_type_hint="access_token"
        )
        assert resp.json() == answer

        def revoke_token_request(url, headers, data):
            assert url == "https://i.b/token"
            return url, headers, data

        sess.register_compliance_hook(
            "revoke_token_request",
            revoke_token_request,
        )
        sess.revoke_token(
            "https://i.b/token", "hi", body="", token_type_hint="access_token"
        )

    def test_introspect_token(self):
        sess = OAuth2Session("a")
        answer = {
            "active": True,
            "client_id": "l238j323ds-23ij4",
            "username": "jdoe",
            "scope": "read write dolphin",
            "sub": "Z5O3upPC88QrAjx00dis",
            "aud": "https://protected.example.net/resource",
            "iss": "https://server.example.com/",
            "exp": 1419356238,
            "iat": 1419350238,
        }
        sess.send = mock_json_response(answer)
        resp = sess.introspect_token("https://i.b/token", "hi")
        assert resp.json() == answer

    def test_client_secret_jwt(self):
        sess = OAuth2Session(
            "id", "secret", token_endpoint_auth_method="client_secret_jwt"
        )
        sess.register_client_auth_method(ClientSecretJWT())

        mock_assertion_response(self, sess)
        token = sess.fetch_token("https://i.b/token")
        assert token == self.token

    def test_client_secret_jwt2(self):
        sess = OAuth2Session(
            "id",
            "secret",
            token_endpoint_auth_method=ClientSecretJWT(),
        )
        mock_assertion_response(self, sess)
        token = sess.fetch_token("https://i.b/token")
        assert token == self.token

    def test_private_key_jwt(self):
        client_secret = read_key_file("rsa_private.pem")
        sess = OAuth2Session(
            "id", client_secret, token_endpoint_auth_method="private_key_jwt"
        )
        sess.register_client_auth_method(PrivateKeyJWT())
        mock_assertion_response(self, sess)
        token = sess.fetch_token("https://i.b/token")
        assert token == self.token

    def test_custom_client_auth_method(self):
        def auth_client(client, method, uri, headers, body):
            uri = add_params_to_uri(
                uri,
                [
                    ("client_id", client.client_id),
                    ("client_secret", client.client_secret),
                ],
            )
            uri = uri + "&" + body
            body = ""
            return uri, headers, body

        sess = OAuth2Session(
            "id", "secret", token_endpoint_auth_method="client_secret_uri"
        )
        sess.register_client_auth_method(("client_secret_uri", auth_client))

        def fake_send(r, **kwargs):
            assert "client_id=" in r.url
            assert "client_secret=" in r.url
            resp = mock.MagicMock()
            resp.status_code = 200
            resp.json = lambda: self.token
            return resp

        sess.send = fake_send
        token = sess.fetch_token("https://i.b/token")
        assert token == self.token

    def test_use_client_token_auth(self):
        import requests

        token = "Bearer " + self.token["access_token"]

        def verifier(r, **kwargs):
            auth_header = r.headers.get("Authorization", None)
            assert auth_header == token
            resp = mock.MagicMock()
            return resp

        client = OAuth2Session(client_id=self.client_id, token=self.token)

        sess = requests.Session()
        sess.send = verifier
        sess.get("https://i.b", auth=client.token_auth)

    def test_use_default_request_timeout(self):
        expected_timeout = 15

        def verifier(r, **kwargs):
            timeout = kwargs.get("timeout")
            assert timeout == expected_timeout
            resp = mock.MagicMock()
            return resp

        client = OAuth2Session(
            client_id=self.client_id,
            token=self.token,
            default_timeout=expected_timeout,
        )

        client.send = verifier
        client.request("GET", "https://i.b", withhold_token=False)

    def test_override_default_request_timeout(self):
        default_timeout = 15
        expected_timeout = 10

        def verifier(r, **kwargs):
            timeout = kwargs.get("timeout")
            assert timeout == expected_timeout
            resp = mock.MagicMock()
            return resp

        client = OAuth2Session(
            client_id=self.client_id,
            token=self.token,
            default_timeout=default_timeout,
        )

        client.send = verifier
        client.request(
            "GET", "https://i.b", withhold_token=False, timeout=expected_timeout
        )
