import time
from unittest import TestCase
from unittest import mock

import pytest

from authlib.integrations.requests_client import AssertionSession


class AssertionSessionTest(TestCase):
    def setUp(self):
        self.token = {
            "token_type": "Bearer",
            "access_token": "a",
            "refresh_token": "b",
            "expires_in": "3600",
            "expires_at": int(time.time()) + 3600,
        }

    def test_refresh_token(self):
        def verifier(r, **kwargs):
            resp = mock.MagicMock()
            resp.status_code = 200
            if r.url == "https://i.b/token":
                assert "assertion=" in r.body
                resp.json = lambda: self.token
            return resp

        sess = AssertionSession(
            "https://i.b/token",
            issuer="foo",
            subject="foo",
            audience="foo",
            alg="HS256",
            key="secret",
        )
        sess.send = verifier
        sess.get("https://i.b")

        # trigger more case
        now = int(time.time())
        sess = AssertionSession(
            "https://i.b/token",
            issuer="foo",
            subject=None,
            audience="foo",
            issued_at=now,
            expires_at=now + 3600,
            header={"alg": "HS256"},
            key="secret",
            scope="email",
            claims={"test_mode": "true"},
        )
        sess.send = verifier
        sess.get("https://i.b")
        # trigger for branch test case
        sess.get("https://i.b")

    def test_without_alg(self):
        sess = AssertionSession(
            "https://i.b/token",
            grant_type=AssertionSession.JWT_BEARER_GRANT_TYPE,
            issuer="foo",
            subject="foo",
            audience="foo",
            key="secret",
        )
        with pytest.raises(ValueError):
            sess.get("https://i.b")
