import unittest

import pytest

from authlib.oauth2.rfc7662 import IntrospectionToken


class IntrospectionTokenTest(unittest.TestCase):
    def test_client_id(self):
        token = IntrospectionToken()
        assert token.client_id is None
        assert token.get_client_id() is None

        token = IntrospectionToken({"client_id": "foo"})
        assert token.client_id == "foo"
        assert token.get_client_id() == "foo"

    def test_scope(self):
        token = IntrospectionToken()
        assert token.scope is None
        assert token.get_scope() is None

        token = IntrospectionToken({"scope": "foo"})
        assert token.scope == "foo"
        assert token.get_scope() == "foo"

    def test_expires_in(self):
        token = IntrospectionToken()
        assert token.get_expires_in() == 0

    def test_expires_at(self):
        token = IntrospectionToken()
        assert token.exp is None
        assert token.get_expires_at() == 0

        token = IntrospectionToken({"exp": 3600})
        assert token.exp == 3600
        assert token.get_expires_at() == 3600

    def test_all_attributes(self):
        # https://tools.ietf.org/html/rfc7662#section-2.2
        token = IntrospectionToken()
        assert token.active is None
        assert token.scope is None
        assert token.client_id is None
        assert token.username is None
        assert token.token_type is None
        assert token.exp is None
        assert token.iat is None
        assert token.nbf is None
        assert token.sub is None
        assert token.aud is None
        assert token.iss is None
        assert token.jti is None

    def test_invalid_attr(self):
        token = IntrospectionToken()
        with pytest.raises(AttributeError):
            token.invalid  # noqa:B018
