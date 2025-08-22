from authlib.common.encoding import to_unicode
from authlib.common.urls import add_params_to_uri


def prepare_grant_uri(
    uri, client_id, request_uri, **kwargs
):
    params = [("client_id", client_id), ("request_uri", request_uri)]

    for k in kwargs:
        if kwargs[k] is not None:
            params.append((to_unicode(k), kwargs[k]))
    return add_params_to_uri(uri, params)