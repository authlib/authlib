import functools
import types
import warnings

import pytest
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError

from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2 import rfc9470
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import (
    AuthorizationSessionMixin as OAuth2AuthorizationSessionMixin,
)
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749.grants import AuthorizationEndpointMixin
from authlib.oauth2.rfc6749.grants import BaseGrant
from authlib.oauth2.rfc6749.grants import TokenEndpointMixin
from authlib.oidc.core import AuthorizationCodeMixin
from authlib.oidc.core import AuthorizationSessionMixin
from authlib.oidc.core import ClaimsParameter
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import OpenIDCode
from authlib.oidc.core import UserInfo
from authlib.oidc.core import get_claim_cls_by_response_type
from authlib.oidc.core import get_requested_acr_values
from authlib.oidc.core import get_requested_sub
from authlib.oidc.core.errors import LoginRequiredError
from authlib.oidc.core.grants.util import call_generate_user_info
from authlib.oidc.core.grants.util import validate_request_prompt
from authlib.oidc.unmet_authentication_requirements import (
    UnmetAuthenticationRequirements,
)

USER = object()


def test_essential_claims():
    claims = CodeIDToken({}, {})
    with pytest.raises(MissingClaimError):
        claims.validate()
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.validate(1000)


def test_validate_auth_time():
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.params = {"max_age": 100}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    claims["auth_time"] = "foo"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_nonce():
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": "1", "exp": 10000, "iat": 100}, {}
    )
    claims.params = {"nonce": "foo"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)
    claims["nonce"] = "bar"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)
    claims["nonce"] = "foo"
    claims.validate(1000)


def test_validate_amr():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "amr": "invalid",
        },
        {},
    )
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


@pytest.mark.parametrize("aud", ["1", ["1", "3"]])
def test_validate_aud(aud):
    """The audience must contain the client_id, even with an azp claim."""
    claims = CodeIDToken(
        {"iss": "1", "sub": "1", "aud": aud, "azp": "2", "exp": 10000, "iat": 100},
        {},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_validate_azp():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": ["1", "2"],
            "exp": 10000,
            "iat": 100,
        },
        {},
    )
    claims.params = {"client_id": "2"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    claims["azp"] = "1"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims["azp"] = "2"
    claims.validate(1000)


def test_validate_at_hash():
    claims = CodeIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "at_hash": "a",
        },
        {},
    )
    claims.params = {"access_token": "a"}

    # invalid alg will raise too
    claims.header = {"alg": "HS222"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims.header = {"alg": "HS256"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_implicit_id_token():
    claims = ImplicitIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "nonce": "a",
        },
        {},
    )
    claims.params = {"access_token": "a"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)


def test_hybrid_id_token():
    claims = HybridIDToken(
        {
            "iss": "1",
            "sub": "1",
            "aud": "1",
            "exp": 10000,
            "iat": 100,
            "nonce": "a",
        },
        {},
    )
    claims.validate(1000)

    claims.params = {"code": "a"}
    with pytest.raises(MissingClaimError):
        claims.validate(1000)

    # invalid alg will raise too
    claims.header = {"alg": "HS222"}
    claims["c_hash"] = "a"
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)

    claims.header = {"alg": "HS256"}
    with pytest.raises(InvalidClaimError):
        claims.validate(1000)


def test_get_claim_cls_by_response_type():
    cls = get_claim_cls_by_response_type("id_token")
    assert cls == ImplicitIDToken
    cls = get_claim_cls_by_response_type("code")
    assert cls == CodeIDToken
    cls = get_claim_cls_by_response_type("code id_token")
    assert cls == HybridIDToken
    cls = get_claim_cls_by_response_type("token id_token")
    assert cls == ImplicitIDToken
    cls = get_claim_cls_by_response_type("token id_token code")
    assert cls == HybridIDToken
    cls = get_claim_cls_by_response_type("code code")
    assert cls is None
    cls = get_claim_cls_by_response_type(None)
    assert cls is None
    cls = get_claim_cls_by_response_type("none")
    assert cls is None


def test_userinfo_getattribute():
    user = UserInfo({"sub": "1"})
    assert user.sub == "1"
    assert user.email is None
    with pytest.raises(AttributeError):
        user.invalid  # noqa: B018


def test_userinfo_validate_locale():
    UserInfo({"sub": "1"}).validate_locale()
    UserInfo({"sub": "1", "locale": "en"}).validate_locale()
    UserInfo({"sub": "1", "locale": "en-US"}).validate_locale()
    UserInfo({"sub": "1", "locale": "zh-Hans-CN"}).validate_locale()
    UserInfo({"sub": "1", "locale": "x-custom"}).validate_locale()

    with pytest.raises(ValueError, match="BCP 47"):
        UserInfo({"sub": "1", "locale": "fr_FR"}).validate_locale()

    with pytest.raises(ValueError, match="BCP 47"):
        UserInfo({"sub": "1", "locale": "toolongsubtag"}).validate_locale()


def test_userinfo_filter_claims():
    """The filter keeps the claims of the scope, and the requested claims."""
    user = UserInfo({"sub": "1", "name": "Jane", "email": "j@example.com"})
    assert user.filter("openid") == {"sub": "1"}
    assert user.filter("openid", {"email": None, "phone_number": None}) == {
        "sub": "1",
        "email": "j@example.com",
    }


def test_claims_parameter_from_request_object():
    """A request object gives the claims parameter as a JSON object."""
    claims_request = {"id_token": {"email": None}}
    payload = types.SimpleNamespace(scope="openid", data={"claims": claims_request})
    request = types.SimpleNamespace(payload=payload)
    grant = types.SimpleNamespace(request=request, ERROR_RESPONSE_FRAGMENT=False)
    ClaimsParameter().validate_claims_parameter(grant, "https://client.test")
    assert request.claims_request == claims_request


def test_empty_claims_parameter():
    """An empty claims parameter is ignored."""
    payload = types.SimpleNamespace(scope="openid", data={"claims": ""})
    grant = types.SimpleNamespace(request=types.SimpleNamespace(payload=payload))
    ClaimsParameter().validate_claims_parameter(grant, "https://client.test/cb")
    assert grant.request.claims_request is None


def test_authorization_code_without_claims_request():
    """By default, an authorization code has no claims request."""
    assert AuthorizationCodeMixin().get_claims_request() is None


def test_generate_user_info_warned_once():
    """The deprecation warning is emitted once per function. A callable that
    cannot be weakly referenced is warned at each call."""

    def generate_user_info(user, scope):
        return UserInfo(sub=user)

    class GenerateUserInfo:
        __slots__ = ()

        def __call__(self, user, scope):
            return UserInfo(sub=user)

    with pytest.warns(AuthlibDeprecationWarning):
        call_generate_user_info(generate_user_info, "1", "openid", None)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        call_generate_user_info(generate_user_info, "1", "openid", None)

    for _ in range(2):
        with pytest.warns(AuthlibDeprecationWarning):
            call_generate_user_info(GenerateUserInfo(), "1", "openid", None)


def test_generate_user_info_partial_without_claims():
    """A generate_user_info callable without a name and without a claims
    argument gets a deprecation warning."""

    def generate_user_info(prefix, user, scope):
        return UserInfo(sub=prefix + user)

    with pytest.warns(AuthlibDeprecationWarning, match="'claims' argument"):
        user_info = call_generate_user_info(
            functools.partial(generate_user_info, "user-"), "1", "openid", None
        )

    assert user_info == {"sub": "user-1"}


def acr_request(data, claims_request=None):
    """Return a request with the given parameters and claims request."""
    payload = types.SimpleNamespace(data=data)
    return types.SimpleNamespace(payload=payload, claims_request=claims_request)


def test_get_requested_acr_values():
    """The acr values of the claims parameter come before acr_values."""
    assert rfc9470.get_requested_acr_values(acr_request({})) == []
    request = acr_request({"acr_values": "gold silver"})
    assert rfc9470.get_requested_acr_values(request) == ["gold", "silver"]
    assert get_requested_acr_values(request) == ["gold", "silver"]

    claims_request = {"id_token": {"acr": {"values": ["platinum"]}}}
    request = acr_request({"acr_values": "gold"}, claims_request)
    assert get_requested_acr_values(request) == ["platinum"]

    claims_request = {"id_token": {"acr": {"value": "platinum"}}}
    assert get_requested_acr_values(acr_request({}, claims_request)) == ["platinum"]

    for acr in (None, {"values": []}, {"values": [1]}):
        claims_request = {"id_token": {"acr": acr}}
        request = acr_request({"acr_values": "gold"}, claims_request)
        assert get_requested_acr_values(request) == ["gold"]


def test_get_requested_sub():
    """The sub of the claims parameter comes before the sub of the
    id_token_hint. Invalid sub values are ignored."""
    request = acr_request({})
    assert get_requested_sub(request) is None

    request.id_token_hint_sub = "1"
    assert get_requested_sub(request) == "1"

    request.claims_request = {"id_token": {"sub": {"value": "2"}}}
    assert get_requested_sub(request) == "2"

    request.claims_request = {"id_token": {"sub": {"value": 3}}}
    assert get_requested_sub(request) == "3"

    for sub in (None, {"value": None}, {"value": True}, {"value": ["2"]}):
        request.claims_request = {"id_token": {"sub": sub}}
        assert get_requested_sub(request) == "1"


def test_unmet_extension_with_unhookable_get_acr():
    """A get_acr that cannot be hooked is left as it is."""

    class AcrMixin:
        def get_acr(self, request):
            return "silver"

    class Session(AcrMixin, OAuth2AuthorizationSessionMixin):
        pass

    session = Session()
    payload = types.SimpleNamespace(scope="openid")
    grant = types.SimpleNamespace(
        authorization_session=session, request=types.SimpleNamespace(payload=payload)
    )
    UnmetAuthenticationRequirements().register_session_hooks(grant)
    assert session.get_acr(None) == "silver"


@pytest.mark.parametrize(
    ("session", "scope"),
    [(None, "openid"), (AuthorizationSessionMixin(), "profile")],
    ids=["no-session", "no-openid-scope"],
)
def test_unmet_extension_without_hook(session, scope):
    """Without a session, or without the openid scope, no hook is
    registered."""
    payload = types.SimpleNamespace(scope=scope)
    grant = types.SimpleNamespace(
        authorization_session=session, request=types.SimpleNamespace(payload=payload)
    )
    UnmetAuthenticationRequirements().register_session_hooks(grant)
    assert not getattr(session, "_hooks", None)


def test_openid_code_on_custom_grant(monkeypatch):
    """OpenIDCode extends a grant that does not inherit AuthorizationCodeGrant."""
    calls = []

    class CustomCodeGrant(AuthorizationEndpointMixin, TokenEndpointMixin, BaseGrant):
        def validate_authorization_request_payload(self, redirect_uri):
            pass

        def validate_consent_request(self):
            return "https://client.test/cb"

        def create_token_response(self):
            return "token response"

    class RecordingOpenIDCode(OpenIDCode):
        def validate_openid_authorization_request(self, grant, redirect_uri):
            calls.append(("validate_openid_authorization_request", redirect_uri))

        def process_token(self, grant, response):
            calls.append(("process_token", response))

    monkeypatch.setattr(
        "authlib.oidc.core.grants.code.validate_request_prompt",
        lambda grant, redirect_uri, **kwargs: calls.append(
            ("validate_request_prompt", redirect_uri)
        ),
    )
    payload = types.SimpleNamespace(scope="openid", data={})
    request = types.SimpleNamespace(payload=payload)
    grant = CustomCodeGrant(request, None)
    RecordingOpenIDCode()(grant)

    grant.validate_authorization_request_payload("https://client.test/cb")
    grant.validate_consent_request()
    grant.create_token_response()

    assert calls == [
        ("validate_openid_authorization_request", None),
        ("validate_request_prompt", "https://client.test/cb"),
        ("process_token", "token response"),
    ]


class FixedSession(AuthorizationSessionMixin):
    """An authorization session with fixed times."""

    def __init__(self, request_time=None, account_selection_needed=False, **times):
        self.request_time = request_time
        self.account_selection_needed = account_selection_needed
        self.times = times

    def get_user(self):
        return USER

    def get_request_time(self, request):
        return self.request_time

    def get_interaction_time(self, request, interaction):
        return self.times.get(interaction)

    def is_account_selection_needed(self, request):
        return self.account_selection_needed


def validate_prompt(
    prompt=None, max_age=None, user=USER, session=None, default_max_age=None
):
    """Validate a request, and return its interactions."""
    data = {"prompt": prompt, "max_age": max_age}
    payload = types.SimpleNamespace(
        data={k: v for k, v in data.items() if v is not None}
    )
    client = types.SimpleNamespace(default_max_age=default_max_age)
    request_time = session.request_time if session else None
    request = types.SimpleNamespace(
        payload=payload, user=user, client=client, request_time=request_time
    )
    grant = types.SimpleNamespace(
        request=request,
        interactions=[],
        server=AuthorizationServer(),
        authorization_session=session,
    )
    validate_request_prompt(grant, None)
    return grant.interactions


@pytest.mark.parametrize("prompt", ["login", "consent", "select_account"])
def test_interaction_after_request_time(prompt):
    """An interaction that the request asks for is done when it happened
    after the start of the request."""
    for interaction_time, request_time in [(1000, 1000), (1000, 999.5)]:
        session = FixedSession(request_time, **{prompt: interaction_time})
        assert validate_prompt(prompt, session=session) == []

    session = FixedSession(1000, **{prompt: 999})
    assert validate_prompt(prompt, session=session) == [prompt]

    session = FixedSession(None, **{prompt: 10**12})
    assert validate_prompt(prompt, session=session) == [prompt]


def test_unknown_auth_time():
    """When the login time is unknown, the user must log in."""
    assert validate_prompt("login", session=FixedSession(0)) == ["login"]


def test_default_max_age():
    """The default_max_age client metadata applies without max_age."""
    session = FixedSession(1061, login=1000)
    assert validate_prompt(session=session, default_max_age=60) == ["login"]
    assert validate_prompt(session=session, default_max_age=-1) == []


def test_max_age_overrides_default_max_age():
    """The max_age parameter overrides default_max_age."""
    session = FixedSession(1061, login=1000)
    interactions = validate_prompt(max_age=3600, session=session, default_max_age=60)
    assert interactions == []


@pytest.mark.parametrize("max_age", [-1, True, 1.5, "abc"])
def test_max_age_invalid_value(max_age):
    """A negative, boolean, float or non-numeric max_age gives
    invalid_request."""
    with pytest.raises(InvalidRequestError):
        validate_prompt(max_age=max_age, session=FixedSession())


def test_account_selection_needed():
    """The authorization session can require the account selection. It is
    done when the user selects an account or logs in after the request
    started."""
    session = FixedSession(1000, login=0, account_selection_needed=True)
    assert validate_prompt(session=session) == ["select_account"]

    for times in [{"select_account": 1000, "login": 0}, {"login": 1000}]:
        session = FixedSession(1000, account_selection_needed=True, **times)
        assert validate_prompt(session=session) == []


@pytest.mark.parametrize(
    "params,interactions",
    [
        ({"prompt": "login"}, ["login"]),
        ({"max_age": 0}, ["login"]),
        ({"default_max_age": 0}, ["login"]),
        ({"max_age": 60}, []),
        ({"prompt": "consent"}, ["consent"]),
    ],
)
def test_without_authorization_session(params, interactions):
    """Without an authorization session, only prompt and max_age=0 add
    interactions, and a deprecation warning is shown."""
    with pytest.warns(AuthlibDeprecationWarning, match="authorization session"):
        assert validate_prompt(**params) == interactions


def test_consent_after_login():
    """After the login, prompt=consent still applies."""
    session = FixedSession(1000, login=1000)
    assert validate_prompt("login consent", session=session) == ["consent"]


def test_login_counts_as_account_selection():
    """A login after the start of the request satisfies
    prompt=select_account."""
    session = FixedSession(1000, login=1000)
    assert validate_prompt("select_account", session=session) == []

    session = FixedSession(1000, login=999)
    assert validate_prompt("select_account", session=session) == ["select_account"]


@pytest.mark.parametrize(
    "user,prompt,interactions",
    [
        (None, "select_account login consent", ["login", "consent"]),
        (USER, "consent select_account", ["select_account", "consent"]),
        (
            USER,
            "consent login select_account",
            ["login", "select_account", "consent"],
        ),
        (USER, "none", []),
    ],
)
def test_interactions(user, prompt, interactions):
    """The interactions are listed in order: login, account selection, then
    consent. An anonymous user selects their account when they log in."""
    session = FixedSession(login=0)
    assert validate_prompt(prompt, user=user, session=session) == interactions


def test_prompt_none_without_user():
    """With prompt=none, a needed login gives login_required right away."""
    with pytest.raises(LoginRequiredError):
        validate_prompt("none", user=None, session=FixedSession())


def test_anonymous_interactions():
    """For an anonymous user, the interactions that prompt asks for are added
    without looking at the session."""

    class FailingSession(FixedSession):
        def get_interaction_time(self, request, interaction):
            assert interaction == "login"

    interactions = validate_prompt(
        "consent select_account", user=None, session=FailingSession()
    )
    assert interactions == ["login", "consent"]
