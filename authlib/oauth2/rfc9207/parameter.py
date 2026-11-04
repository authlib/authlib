from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer


class IssuerParameter:
    def __call__(self, authorization_server):
        authorization_server.register_hook(
            self.add_issuer_parameter,
            after=AuthorizationServer.create_authorization_response,
        )

    def add_issuer_parameter(self, authorization_server, response):
        if self.get_issuer() and response.location:
            # RFC9207 §2
            # In authorization responses to the client, including error responses,
            # an authorization server supporting this specification MUST indicate
            # its identity by including the iss parameter in the response.

            new_location = add_params_to_uri(
                response.location, {"iss": self.get_issuer()}
            )
            response.location = new_location

    def get_issuer(self) -> str | None:
        """Return the issuer URL.
        Developers MAY implement this method if they want to support :rfc:`RFC9207 <9207>`::

            def get_issuer(self) -> str:
                return "https://auth.example.org"
        """
        return None
