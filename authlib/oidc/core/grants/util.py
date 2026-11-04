import time
import weakref

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import to_native
from authlib.deprecate import deprecate
from authlib.oauth2.form_post import FormPost
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.rfc6749 import AuthorizationResponse
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import scope_to_list

from ..errors import LoginRequiredError
from ..util import create_half_hash

_warned_servers = weakref.WeakSet()

#: The authorization request parameters of OpenID Connect, with their JSON
#: types. Per OIDC Core §3.1.2.1, §5.2, §5.5 and §7.2.1.
OPENID_AUTHORIZATION_PARAMETERS = {
    "nonce": str,
    "display": str,
    "prompt": str,
    "max_age": (int, float),
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


def validate_request_prompt(
    grant,
    redirect_uri,
    redirect_fragment=False,
    get_auth_time=None,
    get_request_time=None,
):
    """Validate the ``prompt`` and ``max_age`` parameters, and set ``grant.prompt``.

    ``grant.prompt`` is ``"login"`` when the user must log in, for instance
    when their last authentication is older than ``max_age``.

    :param grant: the grant that validates the authorization request
    :param redirect_uri: the redirect URI of the authorization request
    :param redirect_fragment: whether errors are redirected in the fragment
    :param get_auth_time: a function that takes the request and returns the
        time of the last authentication of its user. Without it, ``max_age``
        is only applied when it is ``0``.
    :param get_request_time: a function that takes the request and returns
        the time the authorization request started. With it, a login after
        this time satisfies ``prompt=login``, and ``max_age`` is measured
        from this time.
    :raises InvalidRequestError: if ``prompt`` contains ``none`` with another
        value, or if ``max_age`` is not a non-negative integer
    :raises LoginRequiredError: if ``prompt`` is ``none`` and the user must
        log in
    """
    prompt = grant.request.payload.data.get("prompt")
    prompts = prompt.split() if prompt else []
    if "none" in prompts and len(prompts) > 1:
        # If this parameter contains none with any other value,
        # an error is returned
        raise InvalidRequestError(
            "Invalid 'prompt' parameter.",
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment,
        )

    max_age = _get_max_age(grant, redirect_uri, redirect_fragment)
    login_required = _is_login_required(
        grant.request, prompts, max_age, get_auth_time, get_request_time
    )
    if not grant.request.user or login_required:
        if "none" in prompts:
            raise LoginRequiredError(
                redirect_uri=redirect_uri, redirect_fragment=redirect_fragment
            )

        grant.prompt = "login"
        return grant

    if "consent" in prompts:
        grant.prompt = "consent"
    elif "select_account" in prompts:
        grant.prompt = "select_account"

    return grant


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


def _get_max_age(grant, redirect_uri, redirect_fragment):
    """Return the maximum authentication age of the request, or ``None``."""
    max_age = grant.request.payload.data.get("max_age")
    # RFC 6749 §3.1: parameters sent without a value MUST be treated as if
    # they were omitted from the request.
    # OIDC Registration §2: the max_age request parameter overrides the
    # default_max_age client metadata.
    if max_age is None or max_age == "":
        default_max_age = getattr(grant.request.client, "default_max_age", None)
        if _is_non_negative_number(default_max_age):
            return default_max_age

        return None

    if isinstance(max_age, str) and max_age.isascii() and max_age.isdigit():
        try:
            return int(max_age)
        except ValueError:
            pass

    elif isinstance(max_age, int) and _is_non_negative_number(max_age):
        return max_age

    raise InvalidRequestError(
        "Invalid 'max_age' parameter.",
        redirect_uri=redirect_uri,
        redirect_fragment=redirect_fragment,
    )


def _is_non_negative_number(value):
    """Tell if a value is a number of seconds."""
    return (
        isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
    )


def get_auth_time_function(obj, base):
    """Return the ``get_auth_time`` method of a grant or extension, or ``None``
    if it does not override the one of ``base``."""
    if type(obj).get_auth_time is base.get_auth_time:
        return None

    return obj.get_auth_time


def resolve_auth_time(obj, base, request):
    """Return the time of the last authentication of the request user, with
    ``get_auth_time``, as an integer. Without it, return the current time."""
    get_auth_time = get_auth_time_function(obj, base)
    if get_auth_time is None:
        return int(time.time())

    auth_time = get_auth_time(request)
    return None if auth_time is None else int(auth_time)


def _is_login_required(request, prompts, max_age, get_auth_time, get_request_time):
    """Tell if the user must log in because of ``prompt=login`` or ``max_age``.

    The request time is read even without a user, so that it is kept from
    the first visit, before the login."""
    # OIDC Core §3.1.2.1: max_age=0 is equivalent to prompt=login.
    fresh_login = "login" in prompts or max_age == 0
    if not fresh_login and max_age is None:
        return False

    if get_auth_time is None:
        return fresh_login

    request_time = get_request_time(request) if get_request_time else None
    if not request.user or (fresh_login and request_time is None):
        return True

    auth_time = get_auth_time(request)
    if auth_time is None:
        return True

    if request_time is None:
        return time.time() - auth_time > max_age

    if fresh_login:
        return int(auth_time) < int(request_time)

    return request_time - auth_time > max_age
