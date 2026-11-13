"""Client-side helpers for the OAuth 2.0 Device Authorization Grant.

:rfc:`8628`
"""

from authlib.common.urls import add_params_to_qs

from ..rfc6749.util import list_to_scope

# https://www.rfc-editor.org/rfc/rfc8628#section-3.4
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


def prepare_device_authorization_request(scope=None, body="", **kwargs):
    """Prepare the device authorization request body.

    Per :rfc:`8628#section-3.1`, the client makes a request to the
    authorization server's device authorization endpoint.

    :param scope: The scope of the access request, as a string or a list.
    :param body: Existing request body to embed parameters in.
    :param kwargs: Extra arguments to embed in the request body.
    :return: The request body as a form URL-encoded string.
    """
    params = []
    if scope:
        params.append(("scope", list_to_scope(scope)))
    for key, value in kwargs.items():
        params.append((key, value))
    return add_params_to_qs(body, params)
