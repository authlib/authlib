import types

from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.grants import BaseGrant
from authlib.oauth2.rfc6749.grants import TokenEndpointMixin
from authlib.oauth2.rfc7636 import CodeChallenge


class CustomCodeGrant(AuthorizationEndpointMixin, TokenEndpointMixin, BaseGrant):
    def validate_authorization_request_payload(self, redirect_uri):
        pass

    def validate_token_request(self):
        pass

    def create_token_response(self):
        pass


class RecordingCodeChallenge(CodeChallenge):
    def __init__(self):
        super().__init__()
        self.calls = []

    def validate_code_challenge(self, grant, redirect_uri):
        self.calls.append(("validate_code_challenge", redirect_uri))

    def validate_code_verifier(self, grant, result):
        self.calls.append(("validate_code_verifier", result))


def test_code_challenge_on_custom_grant():
    """CodeChallenge extends a grant that does not inherit AuthorizationCodeGrant."""
    grant = CustomCodeGrant(types.SimpleNamespace(), None)
    extension = RecordingCodeChallenge()
    extension(grant)

    grant.validate_authorization_request_payload("https://client.test/cb")
    grant.validate_token_request()

    assert extension.calls == [
        ("validate_code_challenge", None),
        ("validate_code_verifier", None),
    ]
