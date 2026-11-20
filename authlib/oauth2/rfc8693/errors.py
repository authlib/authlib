from ..rfc6749.errors import OAuth2Error


class InvalidTargetError(OAuth2Error):
    """The authorization server is unwilling or unable to issue a token for
    any target service indicated by the "resource" or "audience" parameters.

    :rfc:`8693#section-2.2.2`
    """

    error = "invalid_target"
