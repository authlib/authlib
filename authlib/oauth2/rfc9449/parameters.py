from authlib.common.urls import add_params_to_qs
from authlib.common.urls import add_params_to_uri


def add_to_headers(token, headers=None):
    """Add a DPoP Token to the request headers

    Authorization: DPoP h480djs93hd8
    """
    headers = headers or {}
    headers["Authorization"] = f"DPoP {token}"
    return headers


def add_dpop_token(token, uri, headers, body, placement="header"):
    if placement in ("header", "headers"):
        headers = add_to_headers(token, headers)
    else:
        raise ValueError("Unsupported placement") # TODO: Custom error
    return uri, headers, body
