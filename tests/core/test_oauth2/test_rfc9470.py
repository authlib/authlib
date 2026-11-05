import types

import pytest

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import AuthorizationSessionMixin
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc9470 import StepUpAuthentication
from authlib.oauth2.rfc9470 import get_max_age
from authlib.oauth2.rfc9470 import is_login_required

USER = object()


class FixedSession(AuthorizationSessionMixin):
    """An authorization session with fixed times."""

    def __init__(self, auth_time=0):
        self.auth_time = auth_time

    def get_user(self):
        return USER

    def get_interaction_time(self, request, interaction):
        return self.auth_time if interaction == "login" else None


def create_request(user=USER, request_time=None, **data):
    """Return an authorization request with the given parameters."""
    payload = types.SimpleNamespace(data=data)
    return types.SimpleNamespace(payload=payload, user=user, request_time=request_time)


def create_grant(session=None, user=USER, interactions=None, **data):
    """Return a grant for an authorization request."""
    return types.SimpleNamespace(
        request=create_request(user, **data),
        interactions=interactions or [],
        authorization_session=session,
        ERROR_RESPONSE_FRAGMENT=False,
    )


def test_no_age_requested():
    """Without max_age and without a request for a new login, no login is
    required."""
    session = FixedSession(auth_time=None)
    assert not is_login_required(create_request(), session)


def test_anonymous_user():
    """An anonymous user must log in."""
    session = FixedSession()
    assert is_login_required(create_request(user=None), session, max_age=60)


@pytest.mark.parametrize("params", [{"max_age": 0}, {"fresh_login": True}])
def test_new_login(params):
    """A login after the start of the request satisfies a request for a new
    login. Without the request time, a login is always required."""
    for auth_time, request_time in [(1000, 1000), (1000, 999.5)]:
        request = create_request(request_time=request_time)
        assert not is_login_required(request, FixedSession(auth_time), **params)

    request = create_request(request_time=1000)
    assert is_login_required(request, FixedSession(999), **params)
    assert is_login_required(create_request(), FixedSession(10**12), **params)


def test_max_age_from_request_time():
    """max_age is measured from the start of the request, in whole
    seconds."""
    request = create_request(request_time=1060.9)
    assert not is_login_required(request, FixedSession(1000.1), max_age=60)
    request = create_request(request_time=1061)
    assert is_login_required(request, FixedSession(1000), max_age=60)


def test_max_age_from_current_time():
    """Without the request time, max_age is measured from the current
    time."""
    request = create_request()
    assert not is_login_required(request, FixedSession(10**12), max_age=60)
    assert is_login_required(request, FixedSession(0), max_age=60)


def test_unknown_auth_time():
    """When the login time is unknown, the user must log in."""
    request = create_request(request_time=0)
    assert is_login_required(request, FixedSession(None), max_age=60)


def test_validate_max_age():
    """When the authentication is too old, login comes first, and it is not
    added twice."""
    step_up = StepUpAuthentication()
    grant = create_grant(FixedSession(0), interactions=["consent"], max_age="60")
    step_up.validate_max_age(grant, None)
    assert grant.interactions == ["login", "consent"]

    step_up.validate_max_age(grant, None)
    assert grant.interactions == ["login", "consent"]

    grant = create_grant(FixedSession(0))
    step_up.validate_max_age(grant, None)
    assert grant.interactions == []


def test_validate_max_age_without_session():
    """StepUpAuthentication needs an authorization session."""
    grant = create_grant(max_age="60")
    with pytest.raises(ValueError, match="authorization session"):
        StepUpAuthentication().validate_max_age(grant, None)


def test_validate_invalid_max_age():
    """An invalid max_age is redirected to the client, in the fragment when
    the grant sends its errors there."""
    grant = create_grant(FixedSession(), max_age="abc")
    grant.ERROR_RESPONSE_FRAGMENT = True
    with pytest.raises(InvalidRequestError) as exc_info:
        StepUpAuthentication().validate_max_age(grant, "https://client.test")

    assert exc_info.value.redirect_uri == "https://client.test"
    assert exc_info.value.redirect_fragment


@pytest.mark.parametrize(
    "max_age,expected", [(None, None), ("", None), ("60", 60), (60, 60), ("0", 0)]
)
def test_get_max_age(max_age, expected):
    """max_age is a number of seconds. An empty value is ignored."""
    request = create_request(**({} if max_age is None else {"max_age": max_age}))
    assert get_max_age(request, None) == expected


@pytest.mark.parametrize("max_age", ["-1", "1.5", "abc", "١٢", "9" * 5000, -1, True])
def test_get_invalid_max_age(max_age):
    """A max_age that is not a non-negative integer gives invalid_request."""
    with pytest.raises(InvalidRequestError):
        get_max_age(create_request(max_age=max_age), None)


def test_registration():
    """The extension declares its parameters."""
    server = AuthorizationServer()
    server.register_extension(StepUpAuthentication())
    assert server.authorization_parameters["max_age"] is int
    assert server.authorization_parameters["acr_values"] is str


@pytest.mark.parametrize(
    "interactions,expected",
    [
        (["create"], ["create", "login"]),
        (["select_account", "consent"], ["login", "select_account", "consent"]),
    ],
)
def test_login_after_create(interactions, expected):
    """login goes after create, and before the other interactions."""
    grant = create_grant(FixedSession(0), interactions=interactions, max_age="60")
    StepUpAuthentication().validate_max_age(grant, None)
    assert grant.interactions == expected
