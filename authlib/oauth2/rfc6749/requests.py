from collections import defaultdict

from .errors import InsecureTransportError
from .util import normalize_response_type


class OAuth2Payload:
    @property
    def data(self):
        raise NotImplementedError()

    @property
    def datalist(self) -> defaultdict[str, list]:
        raise NotImplementedError()

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get("client_id")

    @property
    def response_type(self) -> str:
        return normalize_response_type(self.data.get("response_type"))

    @property
    def grant_type(self) -> str:
        return self.data.get("grant_type")

    @property
    def redirect_uri(self):
        return self.data.get("redirect_uri")

    @property
    def scope(self) -> str:
        return self.data.get("scope")

    @property
    def state(self):
        return self.data.get("state")


class BasicOAuth2Payload(OAuth2Payload):
    def __init__(self, payload):
        self._data = payload
        self._datalist = {key: [value] for key, value in payload.items()}

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict[str, list]:
        return self._datalist


class OAuth2Request:
    def __init__(self, method: str, uri: str, *, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        #: HTTP headers
        self.headers = headers or {}

        self.payload = None

        #: A hash of the authorization request parameters. It is the same for
        #: all the HTTP requests of one authorization request.
        self.authorization_key = None

        self._request_time = None
        self._request_time_loader = None

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None
        self._scope = None

    @property
    def request_time(self):
        """The time the authorization request started, or ``None``. The
        authorization session gives it on first use."""
        if self._request_time_loader is not None:
            self._request_time = self._request_time_loader(self)
            self._request_time_loader = None

        return self._request_time

    @request_time.setter
    def request_time(self, value):
        self._request_time_loader = None
        self._request_time = value

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def form(self):
        raise NotImplementedError()

    @property
    def scope(self) -> str:
        if self._scope is not None:
            return self._scope
        return self.payload.scope

    @scope.setter
    def scope(self, value: str):
        self._scope = value


class JsonPayload:
    @property
    def data(self):
        """The decoded JSON body, or ``None`` if the body is not valid JSON."""
        raise NotImplementedError()


class JsonRequest:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}
        self.payload = None
