import time

from authlib.oauth2 import OAuth2Request


class LegacyMixin:
    DEFAULT_EXPIRES_IN = 3600

    def resolve_client_private_key(self, client):
        """Resolve the client private key for encoding ``id_token`` Developers
        MUST implement this method in subclass, e.g.::

            import json
            from joserfc.jwk import KeySet


            def resolve_client_private_key(self, client):
                with open(jwks_file_path) as f:
                    data = json.load(f)
                return KeySet.import_key_set(data)
        """
        raise NotImplementedError()

    def get_client_algorithm(self, client):
        """Return the algorithm for encoding ``id_token``.

        Per `OpenID Connect Registration 1.0 Section 2
        <https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata>`_,
        the client metadata ``id_token_signed_response_alg`` takes precedence.
        It falls back to ``RS256``.
        """
        if hasattr(client, "id_token_signed_response_alg") and (
            client_alg := client.id_token_signed_response_alg
        ):
            return client_alg

        return "RS256"

    def get_client_claims(self, client):
        """Return the default client claims for encoding the ``id_token``. Developers
        MUST implement this method in subclass, e.g.::

            def get_client_claims(self, client):
                return {
                    "iss": "your-service-url",
                    "aud": client.get_client_id(),
                }

        Per OpenID Connect Core §2, ``aud`` can be a single string or a list.
        Without ``aud``, the ID token has ``[client_id]``.
        """
        raise NotImplementedError()

    def get_encode_header(self, client):
        return {"alg": self.get_client_algorithm(client)}

    def get_compatible_claims(self, request: OAuth2Request):
        now = int(time.time())

        claims = self.get_client_claims(request.client)
        claims.setdefault("iat", now)
        claims.setdefault("exp", now + self.DEFAULT_EXPIRES_IN)
        claims.setdefault("auth_time", now)
        claims.setdefault("aud", [request.client.get_client_id()])
        return claims
