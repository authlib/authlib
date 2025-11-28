from authlib.oauth2.rfc6750.token import BearerTokenGenerator


class DPoPTokenGenerator(BearerTokenGenerator):
    """DPoP token generator which can create the payload for token response
    by OAuth 2 server. A typical token response would be:

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store
        Pragma: no-cache

        {
            "access_token":"mF_9.B5f-4.1JqM",
            "token_type":"DPoP",
            "expires_in":3600,
            "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
        }
    """

    TOKEN_TYPE = "DPoP"

    def __init__(
        self,
        access_token_generator,
        refresh_token_generator=None,
        expires_generator=None,
    ):
        super().__init__(access_token_generator, refresh_token_generator, expires_generator)
