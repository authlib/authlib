import base64
import unittest

import pytest

from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import util


class OAuth2ParametersTest(unittest.TestCase):
    def test_parse_authorization_code_response(self):
        with pytest.raises(errors.MissingCodeException):
            parameters.parse_authorization_code_response(
                "https://i.b/?state=c",
            )

        with pytest.raises(errors.MismatchingStateException):
            parameters.parse_authorization_code_response(
                "https://i.b/?code=a&state=c",
                "b",
            )

        url = "https://i.b/?code=a&state=c"
        rv = parameters.parse_authorization_code_response(url, "c")
        assert rv == {"code": "a", "state": "c"}

    def test_parse_implicit_response(self):
        with pytest.raises(errors.MissingTokenException):
            parameters.parse_implicit_response(
                "https://i.b/#a=b",
            )

        with pytest.raises(errors.MissingTokenTypeException):
            parameters.parse_implicit_response(
                "https://i.b/#access_token=a",
            )

        with pytest.raises(errors.MismatchingStateException):
            parameters.parse_implicit_response(
                "https://i.b/#access_token=a&token_type=bearer&state=c",
                "abc",
            )

        url = "https://i.b/#access_token=a&token_type=bearer&state=c"
        rv = parameters.parse_implicit_response(url, "c")
        assert rv == {"access_token": "a", "token_type": "bearer", "state": "c"}

    def test_prepare_grant_uri(self):
        grant_uri = parameters.prepare_grant_uri(
            "https://i.b/authorize", "dev", "code", max_age=0
        )
        assert (
            grant_uri
            == "https://i.b/authorize?response_type=code&client_id=dev&max_age=0"
        )


class OAuth2UtilTest(unittest.TestCase):
    def test_list_to_scope(self):
        assert util.list_to_scope(["a", "b"]) == "a b"
        assert util.list_to_scope("a b") == "a b"
        assert util.list_to_scope(None) is None

    def test_scope_to_list(self):
        assert util.scope_to_list("a b") == ["a", "b"]
        assert util.scope_to_list(["a", "b"]) == ["a", "b"]
        assert util.scope_to_list(None) is None

    def test_extract_basic_authorization(self):
        assert util.extract_basic_authorization({}) == (None, None)
        assert util.extract_basic_authorization({"Authorization": "invalid"}) == (
            None,
            None,
        )

        text = "Basic invalid-base64"
        assert util.extract_basic_authorization({"Authorization": text}) == (None, None)

        text = "Basic {}".format(base64.b64encode(b"a").decode())
        assert util.extract_basic_authorization({"Authorization": text}) == ("a", None)

        text = "Basic {}".format(base64.b64encode(b"a:b").decode())
        assert util.extract_basic_authorization({"Authorization": text}) == ("a", "b")
