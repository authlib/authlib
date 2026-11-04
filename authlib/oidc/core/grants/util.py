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

from ..errors import AccountSelectionRequiredError
from ..errors import ConsentRequiredError
from ..errors import LoginRequiredError
from ..util import create_half_hash

_warned_servers = weakref.WeakSet()


def has_multiple_response_types(server):
    """Tell if the MultipleResponseTypes extension is registered on a server."""
    return any(isinstance(ext, MultipleResponseTypes) for ext in server._extensions)


def is_openid_scope(scope):
    scopes = scope_to_list(scope)
    return scopes and "openid" in scopes


def validate_request_prompt(grant, redirect_uri, redirect_fragment=False):
    prompt = grant.request.payload.data.get("prompt")
    end_user = grant.request.user
    if not prompt:
        if not end_user:
            grant.prompt = "login"
        return grant

    if prompt == "none" and not end_user:
        raise LoginRequiredError(
            redirect_uri=redirect_uri, redirect_fragment=redirect_fragment
        )

    prompts = prompt.split()
    if "none" in prompts and len(prompts) > 1:
        # If this parameter contains none with any other value,
        # an error is returned
        raise InvalidRequestError(
            "Invalid 'prompt' parameter.",
            redirect_uri=redirect_uri,
            redirect_fragment=redirect_fragment,
        )

    prompt = _guess_prompt_value(
        end_user, prompts, redirect_uri, redirect_fragment=redirect_fragment
    )
    if prompt:
        grant.prompt = prompt
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


def _guess_prompt_value(end_user, prompts, redirect_uri, redirect_fragment):
    # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

    if not end_user or "login" in prompts:
        return "login"

    if "consent" in prompts:
        if not end_user:
            raise ConsentRequiredError(
                redirect_uri=redirect_uri, redirect_fragment=redirect_fragment
            )
        return "consent"
    elif "select_account" in prompts:
        if not end_user:
            raise AccountSelectionRequiredError(
                redirect_uri=redirect_uri, redirect_fragment=redirect_fragment
            )
        return "select_account"
