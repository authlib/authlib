import json

from starlette.requests import Request as ASGIRequest
from starlette.responses import Response as ASGIResponse


class AsyncMockDispatch:
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

    async def __call__(self, scope, receive, send):
        request = ASGIRequest(scope, receive=receive)

        if self.assert_func:
            await self.assert_func(request)

        response = ASGIResponse(
            status_code=self.status_code,
            content=self.body,
            headers=self.headers,
        )
        await response(scope, receive, send)


def _set_default_content_type(headers, value):
    """Set ``Content-Type`` unless the caller already provided one.

    Accepts a dict or a list of ``(name, value)`` byte pairs, matching the
    two shapes callers pass to the dispatch helpers. Returns a dict that
    ``starlette.responses.Response`` accepts.
    """
    if isinstance(headers, list):
        normalized = {}
        for name, val in headers:
            normalized[name.decode("latin-1")] = val.decode("latin-1")
        headers = normalized
    if not any(name.lower() == "content-type" for name in headers):
        headers = dict(headers)
        headers["Content-Type"] = value
    return headers


class AsyncPathMapDispatch:
    def __init__(self, path_maps, side_effects=None):
        self.path_maps = path_maps
        self.side_effects = side_effects or dict()

    async def __call__(self, scope, receive, send):
        request = ASGIRequest(scope, receive=receive)

        side_effect = self.side_effects.get(request.url.path)
        if side_effect is not None:
            side_effect(request)

        rv = self.path_maps[request.url.path]
        status_code = rv.get("status_code", 200)
        body = rv.get("body")
        headers = rv.get("headers", {})
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers = _set_default_content_type(headers, "application/json")
        else:
            if isinstance(body, str):
                body = body.encode()
            headers = _set_default_content_type(
                headers, "application/x-www-form-urlencoded"
            )

        response = ASGIResponse(
            status_code=status_code,
            content=body,
            headers=headers,
        )
        await response(scope, receive, send)
