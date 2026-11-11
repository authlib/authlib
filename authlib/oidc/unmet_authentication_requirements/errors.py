from authlib.oauth2 import OAuth2Error


class UnmetAuthenticationRequirementsError(OAuth2Error):
    """The Authorization Server is unable to meet the requirements of the
    Relying Party for the authentication of the End-User.

    https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html#rfc.section.1
    """

    error = "unmet_authentication_requirements"
