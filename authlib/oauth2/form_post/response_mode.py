import html
from urllib.parse import urlparse

from ..multiple_response_types import ResponseMode
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Response

FORM_TEMPLATE = (
    "<html><head><title>Redirecting</title></head>"
    '<body onload="javascript:document.forms[0].submit()">'
    '<form method="post" action="{}">{}</form></body></html>'
)

INPUT_TEMPLATE = '<input type="hidden" name="{}" value="{}"/>'


class FormPost(ResponseMode):
    """The ``form_post`` response mode, defined by OAuth 2.0 Form Post
    Response Mode. The user agent sends the authorization response to the
    client with an HTML form that submits itself. Pass it to the extension,
    and add ``form_post`` to its ``response_modes_supported`` metadata::

        class MyMultipleResponseTypes(MultipleResponseTypes):
            def get_server_metadata(self):
                return {"response_modes_supported": ["query", "fragment", "form_post"]}


        server.register_extension(MyMultipleResponseTypes([FormPost()]))

    The redirect URI must use http or https.
    """

    RESPONSE_MODES = ["form_post"]

    def validate(self, grant, redirect_uri):
        """Refuse a redirect URI that does not use http or https.

        :raises InvalidRequestError: without redirection
        """
        self._validate_redirect_uri(redirect_uri)

    def encode(self, response):
        """Render the HTML form that sends the response to the client.

        Per OAuth 2.0 Form Post Response Mode §2, the user agent and the
        intermediaries MUST NOT store or reuse the response.

        :raises InvalidRequestError: if the redirect URI does not use http or
            https
        """
        self._validate_redirect_uri(response.redirect_uri)
        inputs = "".join(
            INPUT_TEMPLATE.format(html.escape(str(name)), html.escape(str(value)))
            for name, value in response.params
        )
        body = FORM_TEMPLATE.format(html.escape(response.redirect_uri), inputs)
        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
            *response.headers,
        ]
        return OAuth2Response(response.status_code or 200, body, headers)

    def _validate_redirect_uri(self, redirect_uri):
        """Refuse a redirect URI that would run a script in the origin of the
        authorization server, such as ``javascript:``.
        """
        if urlparse(redirect_uri).scheme not in ("http", "https"):
            raise InvalidRequestError(
                "The 'form_post' response mode requires an http or https redirect URI."
            )
