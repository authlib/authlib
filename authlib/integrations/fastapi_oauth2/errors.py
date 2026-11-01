from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException


class OAuth2HTTPException(StarletteHTTPException):
    """HTTP exception that carries a ready-made OAuth2 error response.

    FastAPI does not render this exception out of the box, so register the
    bundled handler on the application::

        from fastapi import FastAPI

        from authlib.integrations.flask_oauth2.fastapi_oauth2 import OAuth2HTTPException
        from authlib.integrations.flask_oauth2.fastapi_oauth2 import (
            oauth2_exception_handler,
        )

        app = FastAPI()
        app.add_exception_handler(OAuth2HTTPException, oauth2_exception_handler)
    """

    def __init__(self, status_code, body, headers=None):
        super().__init__(status_code=status_code, detail=body, headers=headers)
        self.body = body


def raise_http_exception(status, body, headers):
    raise OAuth2HTTPException(status, body, headers)


def oauth2_exception_handler(request, exc):
    """FastAPI exception handler that renders :class:`OAuth2HTTPException`
    as the OAuth2 error response it was created with."""
    return Response(
        exc.body,
        status_code=exc.status_code,
        headers=exc.headers,
        media_type="application/json",
    )
