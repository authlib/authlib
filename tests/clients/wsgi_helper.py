import json

from werkzeug.wrappers import Request as WSGIRequest
from werkzeug.wrappers import Response as WSGIResponse


class MockDispatch:
    def __init__(self, body=b"", status_code=200, headers=None, assert_func=None):
        if headers is None:
            headers = {}
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        else:
            if isinstance(body, str):
                body = body.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        self.body = body
        self.status_code = status_code
        self.headers = headers
        self.assert_func = assert_func

    def __call__(self, environ, start_response):
        request = WSGIRequest(environ)

        if self.assert_func:
            self.assert_func(request)

        response = WSGIResponse(
            status=self.status_code,
            response=self.body,
            headers=self.headers,
        )
        return response(environ, start_response)
