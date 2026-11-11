from collections import defaultdict

from django.http import HttpRequest
from django.http import QueryDict
from django.http import RawPostDataException
from django.utils.functional import cached_property

from authlib.common.encoding import json_loads
from authlib.oauth2.rfc6749 import JsonPayload
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Payload
from authlib.oauth2.rfc6749 import OAuth2Request

_URLENCODED = "application/x-www-form-urlencoded"


def _get_form(request: HttpRequest) -> QueryDict:
    """Return the form of the request, for any method.

    Django only parses the form of POST requests.
    """
    if request.method == "POST" or request.content_type.lower() != _URLENCODED:
        return request.POST

    try:
        return QueryDict(request.body)
    except RawPostDataException:
        return request.POST


class DjangoOAuth2Payload(OAuth2Payload):
    def __init__(self, request: HttpRequest):
        self._request = request

    @cached_property
    def data(self):
        data = {}
        data.update(self._request.GET.dict())
        data.update(self._request.POST.dict())
        return data

    @cached_property
    def datalist(self):
        values = defaultdict(list)
        for k in self._request.GET:
            values[k].extend(self._request.GET.getlist(k))
        for k in self._request.POST:
            values[k].extend(self._request.POST.getlist(k))
        return values


class DjangoOAuth2Request(OAuth2Request):
    def __init__(self, request: HttpRequest):
        super().__init__(
            method=request.method,
            uri=request.build_absolute_uri(),
            headers=request.headers,
        )
        self.payload = DjangoOAuth2Payload(request)
        self._request = request

    @property
    def framework_request(self):
        """The Django request of this OAuth 2.0 request."""
        return self._request

    @property
    def args(self):
        return self._request.GET

    @property
    def form(self):
        return self._request.POST


class DjangoJsonPayload(JsonPayload):
    def __init__(self, request: HttpRequest):
        self._request = request

    @cached_property
    def data(self):
        try:
            return json_loads(self._request.body)
        except ValueError:
            return None


class DjangoJsonRequest(JsonRequest):
    def __init__(self, request: HttpRequest):
        super().__init__(request.method, request.build_absolute_uri(), request.headers)
        self._request = request
        self.payload = DjangoJsonPayload(request)

    @cached_property
    def form(self):
        return _get_form(self._request)
