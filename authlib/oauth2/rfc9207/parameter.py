from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer


class IssuerParameter:
    """Authorization server extension for RFC 9207. It adds the ``iss``
    parameter to the authorization responses, in their response mode::

        server.register_extension(IssuerParameter())
    """

    def __call__(self, authorization_server):
        authorization_server.register_hook(
            self.add_issuer_parameter,
            before=AuthorizationServer.encode_authorization_response,
        )

    def add_issuer_parameter(self, authorization_server, response):
        """Add the ``iss`` parameter to an authorization response.

        Per RFC 9207 §2, the authorization server MUST include ``iss`` in its
        authorization responses, including error responses.

        :param authorization_server: the authorization server
        :param response: an :class:`~authlib.oauth2.rfc6749.AuthorizationResponse`
        """
        issuer = self.get_issuer()
        if not issuer:
            return

        params = [(name, value) for name, value in response.params if name != "iss"]
        response.params = [*params, ("iss", issuer)]

    def get_issuer(self) -> str | None:
        """Return the issuer URL.
        Developers MAY implement this method if they want to support :rfc:`RFC9207 <9207>`::

            def get_issuer(self) -> str:
                return "https://auth.example.org"
        """
        return None
