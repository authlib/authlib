from authlib.oidc.core.grants import util
from authlib.oauth2.rfc6749.grants.base import BaseGrant


class DummyRequest:
    def __init__(self, prompt, user=None):
        self.payload = type("P", (), {})()
        self.payload.data = {"prompt": prompt}
        self.user = user


class DummyGrant(BaseGrant):
    def __init__(self, request):
        # server arg not needed for this unit test
        super().__init__(request, None)


def test_validate_request_prompt_sets_create():
    req = DummyRequest("create")
    grant = DummyGrant(req)

    grant = util.validate_request_prompt(grant, redirect_uri=None)
    assert grant.prompt == "create"


def test_validate_request_prompt_with_other_prompts():
    req = DummyRequest("login consent")
    grant = DummyGrant(req)

    grant = util.validate_request_prompt(grant, redirect_uri=None)
    # login should be chosen when no end_user
    assert grant.prompt == "login"
