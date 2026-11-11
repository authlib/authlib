import json
import time
import weakref

from joserfc import jws
from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import to_native
from authlib.deprecate import accepts_argument
from authlib.deprecate import deprecate
from authlib.oauth2.form_post import FormPost
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.rfc6749 import AccessDeniedError
from authlib.oauth2.rfc6749 import AuthorizationResponse
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import scope_to_list
from authlib.oauth2.rfc9470 import get_max_age
from authlib.oauth2.rfc9470 import is_login_required
from authlib.oauth2.rfc9470 import set_authentication_context

from ..errors import AccountSelectionRequiredError
from ..errors import ConsentRequiredError
from ..errors import InteractionRequiredError
from ..errors import LoginRequiredError
from ..util import create_half_hash

_warned_servers = weakref.WeakSet()
_warned_session_servers = weakref.WeakSet()
_warned_user_info_generators = weakref.WeakSet()

_INTERACTION_ERRORS = {
    "login": LoginRequiredError,
    "select_account": AccountSelectionRequiredError,
    "consent": ConsentRequiredError,
}

#: The authorization request parameters of OpenID Connect, with their JSON
#: types. Per OIDC Core §3.1.2.1, §5.2, §5.5 and §7.2.1.
OPENID_AUTHORIZATION_PARAMETERS = {
    "nonce": str,
    "display": str,
    "prompt": str,
    "max_age": int,
    "ui_locales": str,
    "claims_locales": str,
    "id_token_hint": str,
    "login_hint": str,
    "acr_values": str,
    "claims": dict,
    "registration": dict,
}


def has_multiple_response_types(server):
    """Tell if the MultipleResponseTypes extension is registered on a server."""
    return any(isinstance(ext, MultipleResponseTypes) for ext in server._extensions)


def is_openid_scope(scope):
    scopes = scope_to_list(scope)
    return scopes and "openid" in scopes


def get_prompt_values(request):
    """Return the values of the ``prompt`` parameter of a request, as a list.

    :param request: the authorization request
    """
    prompt = request.payload.data.get("prompt")
    return prompt.split() if prompt else []


def validate_request_prompt(
    grant, redirect_uri, redirect_fragment=False, other_user=False
):
    """Validate the ``prompt`` and ``max_age`` parameters, and add the
    interactions they ask for to ``grant.interactions``, in this order:
    ``"login"``, ``"select_account"`` and ``"consent"``.

    An interaction that ``prompt`` asks for is not added when the user went
    through it after the request started. A login after the start of the
    request also counts as an account selection, so an anonymous user only
    has to log in. ``"login"`` is also added when the
    authentication of the user is older than ``max_age`` or the
    ``default_max_age`` client metadata. These times come from the
    authorization session of the grant. Without it, only ``max_age=0`` is
    applied.

    :param grant: the grant that validates the authorization request
    :param redirect_uri: the redirect URI of the authorization request
    :param redirect_fragment: whether errors are redirected in the fragment
    :param other_user: whether the request asks for another user. The user
        must then log in, unless they already did after the request started.
    :raises InvalidRequestError: if ``prompt`` contains ``none`` with another
        value, or if ``max_age`` is not a non-negative integer
    :raises LoginRequiredError: if ``prompt`` is ``none`` and the user must log
        in, or if the request asks for another user than the one who logged in
        after the request started
    """
    prompts = get_prompt_values(grant.request)
    if "none" in prompts and len(prompts) > 1:
        # If this parameter contains none with any other value,
        # an error is returned
        raise InvalidRequestError(
            "Invalid 'prompt' parameter.",
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment,
        )

    max_age = get_max_age(grant.request, redirect_uri, redirect_fragment)
    if max_age is None:
        # OIDC Registration §2: the max_age request parameter overrides the
        # default_max_age client metadata.
        value = getattr(grant.request.client, "default_max_age", None)
        if _is_non_negative_number(value):
            max_age = value

    request = grant.request
    session = grant.authorization_session
    if session is None:
        _warn_missing_authorization_session(grant.server)
        # OIDC Core §3.1.2.1: max_age=0 is equivalent to prompt=login.
        login_required = "login" in prompts or max_age == 0 or other_user
        consent_required = "consent" in prompts
        account_selection_required = "select_account" in prompts and bool(request.user)
    else:
        login_required = is_login_required(
            request,
            session,
            max_age=max_age,
            fresh_login="login" in prompts or other_user,
        )
        consent_required = "consent" in prompts and (
            not request.user or not session.is_interaction_done(request, "consent")
        )
        account_selection_required = _is_account_selection_required(
            request, session, prompts
        )

    login_required = login_required or not request.user
    # OIDC Core §3.1.2.1: with prompt=none, the server MUST NOT display an
    # authentication user interface.
    if login_required and "none" in prompts:
        raise LoginRequiredError(
            redirect_uri=redirect_uri, redirect_fragment=redirect_fragment
        )

    if other_user and not login_required:
        raise LoginRequiredError(
            "The user is not the requested user.",
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment,
        )

    if login_required:
        grant.interactions.append("login")

    if account_selection_required:
        grant.interactions.append("select_account")

    if consent_required:
        grant.interactions.append("consent")

    return grant


def set_silent(grant):
    """Mark the request as silent when ``prompt`` is ``none``.

    Per OIDC Core §3.1.2.1, the server then does not display any user
    interface. The request is done in one HTTP request: its start time is not
    read, and its errors are redirected even if the user is not logged in.

    :param grant: the grant that validates the authorization request
    """
    grant.silent = get_prompt_values(grant.request) == ["none"]


def validate_prompt_none(grant, redirect_fragment=False):
    """Raise an error when ``prompt`` is ``none`` and the user must go
    through an interaction.

    Per OIDC Core §3.1.2.1, with ``prompt=none`` the server MUST NOT display
    any authentication or consent user interface. The error tells which
    interaction is needed (OIDC Core §3.1.2.6).

    :param grant: the grant that validates the authorization request
    :param redirect_fragment: whether errors are redirected in the fragment
    :raises LoginRequiredError: if the user must log in
    :raises AccountSelectionRequiredError: if the user must select an account
    :raises ConsentRequiredError: if the user must give their consent
    :raises InteractionRequiredError: for any other interaction
    """
    if not grant.interactions or "none" not in get_prompt_values(grant.request):
        return

    error_class = _INTERACTION_ERRORS.get(
        grant.interactions[0], InteractionRequiredError
    )
    raise error_class(
        redirect_uri=grant.redirect_uri, redirect_fragment=redirect_fragment
    )


def validate_response_mode(grant, redirect_uri):
    """Validate the response mode of an implicit or hybrid authorization request.

    Per OAuth 2.0 Multiple Response Type Encoding Practices §3 and §5, the
    ``query`` response mode MUST NOT be used with the ``id_token`` response
    type and its combinations.

    With ``form_post``, the user-agent submits an HTML form to the redirect
    URI. A ``javascript:`` redirect URI would then run a script in the
    origin of the authorization server.

    :param grant: the grant that validates the authorization request
    :param redirect_uri: the redirect URI of the authorization request
    :raises InvalidRequestError: if the response mode is not ``fragment`` or
        ``form_post``, with a redirection in the fragment, or if it is
        ``form_post`` and the redirect URI scheme is not http or https,
        without redirection
    """
    server = grant.server
    if has_multiple_response_types(server):
        return

    if "response_mode" in grant.request.payload.data and server not in _warned_servers:
        _warned_servers.add(server)
        deprecate(
            "Using 'response_mode' with the OpenID Connect implicit and hybrid "
            "grants without the 'MultipleResponseTypes' extension is deprecated. "
            "Register it with 'server.register_extension(MultipleResponseTypes())'. "
            "For the form_post response mode, pass it 'FormPost()' and add "
            "'form_post' to its 'response_modes_supported' metadata.",
            version="1.11",
        )

    response_mode = grant.request.payload.data.get("response_mode", grant.RESPONSE_MODE)
    if response_mode not in ("fragment", "form_post"):
        raise InvalidRequestError(
            "The 'response_mode' value is not supported for this response type.",
            redirect_uri=redirect_uri,
            redirect_fragment=True,
        )

    if response_mode == "form_post":
        FormPost().validate(grant, redirect_uri)


def validate_nonce(request, exists_nonce, required=False):
    nonce = request.payload.data.get("nonce")
    if not nonce:
        if required:
            raise InvalidRequestError("Missing 'nonce' in request.")
        return True

    if exists_nonce(nonce, request):
        raise InvalidRequestError("Replay attack")


def generate_id_token(
    token,
    user_info,
    key,
    iss,
    aud,
    alg="RS256",
    exp=3600,
    nonce=None,
    auth_time=None,
    acr=None,
    amr=None,
    code=None,
    kid=None,
):
    now = int(time.time())
    if auth_time is None:
        auth_time = now

    header = {"alg": alg}
    if kid:
        header["kid"] = kid

    payload = {
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp,
        "auth_time": auth_time,
    }
    if nonce:
        payload["nonce"] = nonce

    if acr:
        payload["acr"] = acr

    if amr:
        payload["amr"] = amr

    if code:
        c_hash = create_half_hash(code, alg)
        if c_hash is not None:
            payload["c_hash"] = to_native(c_hash)

    access_token = token.get("access_token")
    if access_token:
        at_hash = create_half_hash(access_token, alg)
        if at_hash is not None:
            payload["at_hash"] = to_native(at_hash)

    payload.update(user_info)
    if alg == "none":
        private_key = None
    else:
        private_key = import_any_key(key)

    return jwt.encode(header, payload, private_key, [alg])


def create_response_mode_response(redirect_uri, params, response_mode):
    """Deprecated. Return an ``AuthorizationResponse`` instead."""
    deprecate(
        "'create_response_mode_response' is deprecated. "
        "Return an 'AuthorizationResponse' instead.",
        version="1.11",
    )
    response = AuthorizationResponse(redirect_uri, params, response_mode)
    if response_mode == "form_post":
        return FormPost().encode(response)

    return response


def _is_non_negative_number(value):
    """Tell if a value is a number of seconds."""
    return (
        isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    )


def _is_account_selection_required(request, session, prompts):
    """Tell if the user must select an account. An anonymous user selects
    their account when they log in."""
    if not request.user:
        return False

    is_needed = getattr(session, "is_account_selection_needed", None)
    if "select_account" not in prompts and not (is_needed and is_needed(request)):
        return False

    return not (
        session.is_interaction_done(request, "select_account")
        or session.is_interaction_done(request, "login")
    )


def _warn_missing_authorization_session(server):
    """Warn once per server that the OpenID Connect grants need an
    authorization session."""
    if server in _warned_session_servers:
        return

    _warned_session_servers.add(server)
    deprecate(
        "Using the OpenID Connect grants without an authorization session is "
        "deprecated. Pass an 'AuthorizationSessionMixin' to "
        "'get_consent_grant(session=...)', to enforce 'max_age' and to set the "
        "'auth_time' claim.",
        version="1.11",
    )


def resolve_auth_time(grant):
    """Return the time of the last authentication of the user, as an
    integer, from the authorization session. Without it, return the current
    time."""
    session = grant.authorization_session
    if session is None:
        return int(time.time())

    auth_time = session.get_interaction_time(grant.request, "login")
    return None if auth_time is None else int(auth_time)


def resolve_authentication(grant, redirect_uri):
    """Set the auth_time, acr and amr of the request, from the authorization
    session."""
    grant.request.auth_time = resolve_auth_time(grant)
    set_authentication_context(grant, redirect_uri)
    validate_essential_acr(grant, redirect_uri)


def _get_acr_request(claims_request):
    """Return the request of the acr claim in the id_token member of a claims
    request, or None."""
    acr = (get_requested_claims(claims_request, "id_token") or {}).get("acr")
    return acr if isinstance(acr, dict) else None


def get_claims_parameter_acr_values(claims_request):
    """Return the ``acr`` values that the ``id_token`` member of a ``claims``
    request asks for, with ``values`` or ``value``, or ``None``."""
    return _get_acr_values(_get_acr_request(claims_request) or {})


def _get_acr_values(acr):
    """Return the values of an acr claim request, or None."""
    values = acr.get("values")
    if not isinstance(values, list):
        values = [acr.get("value")]

    values = [value for value in values if isinstance(value, str)]
    return values or None


def is_essential_acr_unmet(request, acr):
    """Tell whether the ``claims`` parameter of the request asks for an
    essential ``acr`` with values, and ``acr`` is not one of them.

    :param request: the authorization request
    :param acr: the ``acr`` of the authentication of the user
    """
    acr_request = _get_acr_request(getattr(request, "claims_request", None))
    if acr_request is None or acr_request.get("essential") is not True:
        return False

    values = _get_acr_values(acr_request)
    return values is not None and acr not in values


def validate_essential_acr(grant, redirect_uri):
    """Refuse the request when the ``claims`` parameter asks for an essential
    ``acr`` that the authentication does not satisfy.

    Per OIDC Core §5.5.1.1, the server MUST then treat the outcome as a failed
    authentication attempt. The request is refused with ``access_denied``,
    redirected to the client.

    :param grant: the grant that creates the authorization response
    :param redirect_uri: the redirect URI of the authorization request
    :raises AccessDeniedError: if the ``acr`` of the request is not one of the
        requested values
    """
    if not is_essential_acr_unmet(grant.request, grant.request.acr):
        return

    raise AccessDeniedError(
        "The authentication does not satisfy the requested 'acr' values.",
        redirect_uri=redirect_uri,
        redirect_fragment=grant.ERROR_RESPONSE_FRAGMENT,
    )


def set_id_token_hint_sub(
    request, generator, redirect_uri=None, redirect_fragment=False
):
    """Set ``request.id_token_hint_sub`` to the ``sub`` of the
    ``id_token_hint`` parameter, or to ``None``.

    Per OIDC Core §3.1.2.1, the hint is an ID token that the server issued
    before. Its signature is checked with the key and the algorithm of the ID
    tokens of the client. When these ID tokens are not signed, the ``sub`` is
    read without a check. Its expiration time is not checked.

    :param request: the authorization request
    :param generator: the extension or the grant that generates the ID tokens
    :param redirect_uri: the redirect URI of the authorization request
    :param redirect_fragment: whether errors are redirected in the fragment
    :raises InvalidRequestError: if the hint is not an ID token of the server
    """
    request.id_token_hint_sub = None
    hint = request.payload.data.get("id_token_hint")
    if not hint:
        return

    sub = _decode_id_token_hint(hint, generator, request.client)
    if sub is None:
        raise InvalidRequestError(
            "Invalid 'id_token_hint' parameter.",
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment,
        )

    request.id_token_hint_sub = sub


def _decode_id_token_hint(hint, generator, client):
    """Return the sub of an ID token of the client, or None. The signature of
    an unsigned ID token is not checked."""
    alg = generator.get_client_algorithm(client)
    key = None
    if alg != "none":
        key = import_any_key(generator.resolve_client_private_key(client))

    try:
        if key is None:
            claims = json.loads(jws.extract_compact(hint.encode()).payload)
        else:
            claims = jwt.decode(hint, key, algorithms=[alg]).claims
    except (JoseError, ValueError):
        return None

    if not isinstance(claims, dict):
        return None

    return _normalize_sub(claims.get("sub"))


def _normalize_sub(sub):
    """Return a sub as a string, or None. Integers are accepted, because
    applications often use the id of the user."""
    if isinstance(sub, int) and not isinstance(sub, bool):
        return str(sub)

    return sub if isinstance(sub, str) else None


def get_requested_subs(request):
    """Return the ``sub`` values that the request asks for: the ``sub`` claim
    of the ``claims`` parameter, then the ``sub`` of the ``id_token_hint``.

    :param request: the authorization request
    """
    claims_request = getattr(request, "claims_request", None)
    sub_request = (get_requested_claims(claims_request, "id_token") or {}).get("sub")
    if not isinstance(sub_request, dict):
        sub_request = {}

    subs = [
        _normalize_sub(sub_request.get("value")),
        getattr(request, "id_token_hint_sub", None),
    ]
    return [sub for sub in subs if sub is not None]


def is_requested_sub_unmet(request, generator):
    """Tell whether the request asks for a ``sub`` that is not the ``sub`` of
    ``request.user``. The ``sub`` of the user comes from
    ``generate_user_info``.

    :param request: the authorization request
    :param generator: the extension or the grant that generates the ID tokens
    """
    requested = get_requested_subs(request)
    if not requested or not request.user:
        return False

    user_info = call_generate_user_info(
        generator.generate_user_info, request.user, request.scope, None
    )
    sub = _normalize_sub(user_info.get("sub"))
    return any(value != sub for value in requested)


def validate_requested_sub(grant, generator, redirect_uri):
    """Refuse the request when it asks for another user than the user who
    grants it.

    Per OIDC Core §5.5.1, the server MUST NOT return an ID token or an access
    token for another user than the one of the ``sub`` claim request or of
    the ``id_token_hint``. Per OIDC Core §3.1.2.1, the error is
    ``login_required``, redirected to the client.

    :param grant: the grant that creates the authorization response
    :param generator: the extension or the grant that generates the ID tokens
    :param redirect_uri: the redirect URI of the authorization request
    :raises LoginRequiredError: if the user is not the requested user
    """
    if not is_requested_sub_unmet(grant.request, generator):
        return

    raise LoginRequiredError(
        "The user is not the requested user.",
        redirect_uri=redirect_uri,
        redirect_fragment=grant.ERROR_RESPONSE_FRAGMENT,
    )


def get_requested_claims(claims_request, member):
    """Return a member of a ``claims`` request, such as ``"id_token"`` or
    ``"userinfo"``, or ``None``."""
    if not claims_request:
        return None

    return claims_request.get(member)


def call_generate_user_info(generate_user_info, user, scope, claims):
    """Call a ``generate_user_info`` method with the requested claims. A method
    without a ``claims`` argument gets a deprecation warning, once."""
    if accepts_argument(generate_user_info, "claims"):
        return generate_user_info(user, scope, claims=claims)

    function = getattr(generate_user_info, "__func__", generate_user_info)
    if not _is_warned(function):
        name = getattr(function, "__qualname__", None) or repr(function)
        deprecate(
            f"'{name}' does not accept a 'claims' argument. "
            "In 1.11, it will always receive it.",
        )

    return generate_user_info(user, scope)


def _is_warned(function):
    """Tell whether the deprecation of a generate_user_info function was
    already emitted, and remember it. A function that cannot be weakly
    referenced is always warned."""
    try:
        if function in _warned_user_info_generators:
            return True

        _warned_user_info_generators.add(function)
    except TypeError:
        pass

    return False
