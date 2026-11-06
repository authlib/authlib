from collections import defaultdict
from functools import cached_property

from fastapi import Request
from starlette.datastructures import FormData

from authlib.oauth2.rfc6749 import JsonPayload
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Payload
from authlib.oauth2.rfc6749 import OAuth2Request


class FastApiOAuth2Payload(OAuth2Payload):
    def __init__(self, request: Request, form=None):
        self._request = request
        self._form = form

    @property
    def data(self):
        if self._form is None:
            return self._request.query_params
        return FormData(
            list(self._request.query_params.multi_items())
            + list(self._form.multi_items())
        )

    @cached_property
    def datalist(self):
        values = defaultdict(list)
        for k in self.data:
            values[k].extend(self.data.getlist(k))
        return values


class FastApiOAuth2Request(OAuth2Request):
    def __init__(self, request: Request, form=None):
        super().__init__(
            method=request.method,
            uri=str(
                request.url.replace(query="")
            ),  # Strip query parameters from the URI
            headers=request.headers,
        )
        self._request = request
        self._form = form
        self.payload = FastApiOAuth2Payload(request, form)

    @property
    def args(self):
        return self._request.query_params

    @property
    def form(self):
        return self._form


async def create_oauth2_request(request: Request) -> FastApiOAuth2Request:
    """Create a :class:`FastApiOAuth2Request` from a FastAPI/Starlette
    request. Form data, if any, is parsed with ``await request.form()``."""
    form = None
    content_type = request.headers.get("content-type", "")
    if (
        "application/x-www-form-urlencoded" in content_type
        or "multipart/form-data" in content_type
    ):
        form = await request.form()
    return FastApiOAuth2Request(request, form)


class FastApiJsonPayload(JsonPayload):
    def __init__(self, request: Request, data=None):
        self._request = request
        self._data = data

    @property
    def data(self):
        return self._data


class FastApiJsonRequest(JsonRequest):
    def __init__(self, request: Request, data=None):
        super().__init__(request.method, str(request.url), request.headers)
        self.payload = FastApiJsonPayload(request, data)


async def create_json_request(request: Request) -> FastApiJsonRequest:
    """Create a :class:`FastApiJsonRequest` from a FastAPI/Starlette request."""
    try:
        data = await request.json()
    except Exception:
        data = None
    return FastApiJsonRequest(request, data)
